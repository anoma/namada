//! A tx for a PoS unbond that removes staked tokens from a self-bond or a
//! delegation to be withdrawn in or after unbonding epoch.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let withdraw = transaction::pos::Withdraw::try_from_slice(&data[..])
        .wrap_err("failed to decode Withdraw")?;

    let slashed =
        ctx.withdraw_tokens(withdraw.source.as_ref(), &withdraw.validator)?;
    if slashed != token::Amount::default() {
        debug_log!("Withdrawal slashed for {}", slashed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use namada::ledger::pos::PosParams;
    use namada::proto::Tx;
    use namada::types::storage::Epoch;
    use namada_tests::log::test;
    use namada_tests::native_vp::pos::init_pos;
    use namada_tests::native_vp::TestNativeVpEnv;
    use namada_tests::tx::*;
    use namada_tx_prelude::address::testing::{
        arb_established_address, arb_non_internal_address,
    };
    use namada_tx_prelude::address::InternalAddress;
    use namada_tx_prelude::key::testing::arb_common_keypair;
    use namada_tx_prelude::key::RefTo;
    use namada_tx_prelude::proof_of_stake::parameters::testing::arb_pos_params;
    use namada_vp_prelude::proof_of_stake::{
        staking_token_address, BondId, GenesisValidator, PosVP,
    };
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// In this test we setup the ledger and PoS system with an arbitrary
        /// initial state with 1 genesis validator, a delegation bond if the
        /// withdrawal is for a delegation, arbitrary PoS parameters and
        /// a we generate an arbitrary withdrawal that we'd like to apply.
        ///
        /// After we apply the withdrawal, we're checking that all the storage
        /// values in PoS system have been updated as expected and then we also
        /// check that this transaction is accepted by the PoS validity
        /// predicate.
        #[test]
        fn test_tx_withdraw(
        (initial_stake, unbonded_amount) in arb_initial_stake_and_unbonded_amount(),
        withdraw in arb_withdraw(),
        // A key to sign the transaction
        key in arb_common_keypair(),
        pos_params in arb_pos_params()) {
            test_tx_withdraw_aux(initial_stake, unbonded_amount, withdraw, key,
                pos_params).unwrap()
        }
    }

    fn test_tx_withdraw_aux(
        initial_stake: token::Amount,
        unbonded_amount: token::Amount,
        withdraw: transaction::pos::Withdraw,
        key: key::common::SecretKey,
        pos_params: PosParams,
    ) -> TxResult {
        let is_delegation = matches!(
            &withdraw.source, Some(source) if *source != withdraw.validator);
        let staking_reward_address = address::testing::established_address_1();
        let consensus_key = key::testing::keypair_1().ref_to();
        let staking_reward_key = key::testing::keypair_2().ref_to();

        let genesis_validators = [GenesisValidator {
            address: withdraw.validator.clone(),
            staking_reward_address,
            tokens: if is_delegation {
                // If we're withdrawing a delegation, we'll give the initial
                // stake to the delegation instead of the
                // validator
                token::Amount::default()
            } else {
                initial_stake
            },
            consensus_key,
            staking_reward_key,
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        tx_host_env::with(|tx_env| {
            if is_delegation {
                let source = withdraw.source.as_ref().unwrap();
                tx_env.spawn_accounts([source]);

                // To allow to unbond delegation, there must be a delegation
                // bond first.
                // First, credit the bond's source with the initial stake,
                // before we initialize the bond below
                tx_env.credit_tokens(
                    source,
                    &staking_token_address(),
                    initial_stake,
                );
            }
        });

        if is_delegation {
            // Initialize the delegation - unlike genesis validator's self-bond,
            // this happens at pipeline offset
            ctx().bond_tokens(
                withdraw.source.as_ref(),
                &withdraw.validator,
                initial_stake,
            )?;
        }

        // Unbond the `unbonded_amount` at the starting epoch 0
        ctx().unbond_tokens(
            withdraw.source.as_ref(),
            &withdraw.validator,
            unbonded_amount,
        )?;

        tx_host_env::commit_tx_and_block();

        // Fast forward to unbonding offset epoch so that it's possible to
        // withdraw the unbonded tokens
        tx_host_env::with(|env| {
            for _ in 0..pos_params.unbonding_len {
                env.storage.block.epoch = env.storage.block.epoch.next();
            }
        });
        assert_eq!(
            tx_host_env::with(|env| env.storage.block.epoch),
            Epoch(pos_params.unbonding_len)
        );

        let tx_code = vec![];
        let tx_data = withdraw.try_to_vec().unwrap();
        let tx = Tx::new(tx_code, Some(tx_data));
        let signed_tx = tx.sign(&key);
        let tx_data = signed_tx.data.unwrap();

        // Read data before we apply tx:
        let pos_balance_key = token::balance_key(
            &staking_token_address(),
            &Address::Internal(InternalAddress::PoS),
        );
        let pos_balance_pre: token::Amount = ctx()
            .read(&pos_balance_key)?
            .expect("PoS must have balance");
        assert_eq!(pos_balance_pre, initial_stake);
        let unbond_src = withdraw
            .source
            .clone()
            .unwrap_or_else(|| withdraw.validator.clone());
        let unbond_id = BondId {
            validator: withdraw.validator,
            source: unbond_src,
        };
        let unbonds_pre = ctx().read_unbond(&unbond_id)?.unwrap();
        assert_eq!(
            unbonds_pre.get(pos_params.unbonding_len).unwrap().sum(),
            unbonded_amount
        );

        apply_tx(ctx(), tx_data)?;

        // Read the data after the tx is executed
        let unbonds_post = ctx().read_unbond(&unbond_id)?;
        assert!(
            unbonds_post.is_none(),
            "Because we're withdraw the full unbonded amount, there should be \
             no unbonds left"
        );
        let pos_balance_post: token::Amount = ctx()
            .read(&pos_balance_key)?
            .expect("PoS must have balance");
        assert_eq!(pos_balance_pre - pos_balance_post, unbonded_amount);

        // Use the tx_env to run PoS VP
        let tx_env = tx_host_env::take();
        let vp_env = TestNativeVpEnv::from_tx_env(tx_env, address::POS);
        let result = vp_env.validate_tx(PosVP::new);
        let result =
            result.expect("Validation of valid changes must not fail!");
        assert!(
            result,
            "PoS Validity predicate must accept this transaction"
        );
        Ok(())
    }

    fn arb_initial_stake_and_unbonded_amount()
    -> impl Strategy<Value = (token::Amount, token::Amount)> {
        // Generate initial stake
        token::testing::arb_amount().prop_flat_map(|initial_stake| {
            // Use the initial stake to limit the unbonded amount from the stake
            let unbonded_amount =
                token::testing::arb_amount_ceiled(initial_stake.into());
            // Use the generated initial stake too too
            (Just(initial_stake), unbonded_amount)
        })
    }

    fn arb_withdraw() -> impl Strategy<Value = transaction::pos::Withdraw> {
        (
            arb_established_address(),
            prop::option::of(arb_non_internal_address()),
        )
            .prop_map(|(validator, source)| {
                transaction::pos::Withdraw {
                    validator: Address::Established(validator),
                    source,
                }
            })
    }
}
