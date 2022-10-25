//! A tx for a PoS unbond that removes staked tokens from a self-bond or a
//! delegation to be withdrawn in or after unbonding epoch.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let unbond = transaction::pos::Unbond::try_from_slice(&data[..])
        .wrap_err("failed to decode Unbond")?;

    ctx.unbond_tokens(unbond.source.as_ref(), &unbond.validator, unbond.amount)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use namada::ledger::pos::PosParams;
    use namada::proto::Tx;
    use namada::types::storage::Epoch;
    use namada_tests::log::test;
    use namada_tests::native_vp::pos::init_pos;
    use namada_tests::native_vp::TestNativeVpEnv;
    use namada_tests::tx::*;
    use namada_tx_prelude::address::InternalAddress;
    use namada_tx_prelude::key::testing::arb_common_keypair;
    use namada_tx_prelude::key::RefTo;
    use namada_tx_prelude::proof_of_stake::parameters::testing::arb_pos_params;
    use namada_tx_prelude::token;
    use namada_vp_prelude::proof_of_stake::types::{Bond, Unbond};
    use namada_vp_prelude::proof_of_stake::{
        staking_token_address, BondId, GenesisValidator, PosVP,
    };
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// In this test we setup the ledger and PoS system with an arbitrary
        /// initial state with 1 genesis validator, a delegation bond if the
        /// unbond is for a delegation, arbitrary PoS parameters, and
        /// we generate an arbitrary unbond that we'd like to apply.
        ///
        /// After we apply the unbond, we check that all the storage values
        /// in PoS system have been updated as expected and then we also check
        /// that this transaction is accepted by the PoS validity predicate.
        #[test]
        fn test_tx_unbond(
        (initial_stake, unbond) in arb_initial_stake_and_unbond(),
        // A key to sign the transaction
        key in arb_common_keypair(),
        pos_params in arb_pos_params()) {
            test_tx_unbond_aux(initial_stake, unbond, key, pos_params).unwrap()
        }
    }

    fn test_tx_unbond_aux(
        initial_stake: token::Amount,
        unbond: transaction::pos::Unbond,
        key: key::common::SecretKey,
        pos_params: PosParams,
    ) -> TxResult {
        let is_delegation = matches!(
            &unbond.source, Some(source) if *source != unbond.validator);
        let consensus_key = key::testing::keypair_1().ref_to();
        let commission_rate = rust_decimal::Decimal::new(5, 2);
        let max_commission_rate_change = rust_decimal::Decimal::new(1, 2);

        let genesis_validators = [GenesisValidator {
            address: unbond.validator.clone(),
            tokens: if is_delegation {
                // If we're unbonding a delegation, we'll give the initial stake
                // to the delegation instead of the validator
                token::Amount::default()
            } else {
                initial_stake
            },
            consensus_key,
            commission_rate,
            max_commission_rate_change,
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        tx_host_env::with(|tx_env| {
            if is_delegation {
                let source = unbond.source.as_ref().unwrap();
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

        // Initialize the delegation if it is the case - unlike genesis
        // validator's self-bond, this happens at pipeline offset
        if is_delegation {
            ctx().bond_tokens(
                unbond.source.as_ref(),
                &unbond.validator,
                initial_stake,
            )?;
        }
        tx_host_env::commit_tx_and_block();

        let tx_code = vec![];
        let tx_data = unbond.try_to_vec().unwrap();
        let tx = Tx::new(tx_code, Some(tx_data));
        let signed_tx = tx.sign(&key);
        let tx_data = signed_tx.data.unwrap();

        let unbond_src = unbond
            .source
            .clone()
            .unwrap_or_else(|| unbond.validator.clone());
        let unbond_id = BondId {
            validator: unbond.validator.clone(),
            source: unbond_src,
        };

        let pos_balance_key = token::balance_key(
            &staking_token_address(),
            &Address::Internal(InternalAddress::PoS),
        );
        let pos_balance_pre: token::Amount = ctx()
            .read(&pos_balance_key)?
            .expect("PoS must have balance");
        assert_eq!(pos_balance_pre, initial_stake);

        let total_deltas_pre = ctx().read_total_deltas()?;
        let validator_sets_pre = ctx().read_validator_set()?;
        let validator_deltas_pre =
            ctx().read_validator_deltas(&unbond.validator)?.unwrap();
        let bonds_pre = ctx().read_bond(&unbond_id)?.unwrap();
        dbg!(&bonds_pre);

        // Apply the unbond tx
        apply_tx(ctx(), tx_data)?;

        // Read the data after the tx is executed.
        // The following storage keys should be updated:

        //     - `#{PoS}/validator/#{validator}/deltas`
        //     - `#{PoS}/total_deltas`
        //     - `#{PoS}/validator_set`
        let total_deltas_post = ctx().read_total_deltas()?;
        let validator_deltas_post =
            ctx().read_validator_deltas(&unbond.validator)?;
        let validator_sets_post = ctx().read_validator_set()?;

        let expected_amount_before_pipeline = if is_delegation {
            // When this is a delegation, there will be no bond until pipeline
            0.into()
        } else {
            // Before pipeline offset, there can only be self-bond
            initial_stake
        };

        // Before pipeline offset, there can only be self-bond for genesis
        // validator. In case of a delegation the state is setup so that there
        // is no bond until pipeline offset.
        //
        // TODO: check if this test is correct (0 -> unbonding?)
        for epoch in 0..pos_params.pipeline_len {
            assert_eq!(
                validator_deltas_post.as_ref().unwrap().get(epoch),
                Some(expected_amount_before_pipeline.into()),
                "The validator deltas before the pipeline offset must not \
                 change - checking in epoch: {epoch}"
            );
            assert_eq!(
                total_deltas_post.get(epoch),
                Some(expected_amount_before_pipeline.into()),
                "The total deltas before the pipeline offset must not change \
                 - checking in epoch: {epoch}"
            );
            assert_eq!(
                validator_sets_pre.get(epoch),
                validator_sets_post.get(epoch),
                "Validator set before pipeline offset must not change - \
                 checking epoch {epoch}"
            );
        }

        // At and after pipeline offset, there can be either delegation or
        // self-bond, both of which are initialized to the same `initial_stake`
        for epoch in pos_params.pipeline_len..pos_params.unbonding_len {
            assert_eq!(
                validator_deltas_post.as_ref().unwrap().get(epoch),
                Some(initial_stake.into()),
                "The validator deltas at and after the unbonding offset must \
                 have changed - checking in epoch: {epoch}"
            );
            assert_eq!(
                total_deltas_post.get(epoch),
                Some(initial_stake.into()),
                "The total deltas at and after the unbonding offset must have \
                 changed - checking in epoch: {epoch}"
            );
            assert_eq!(
                validator_sets_pre.get(epoch),
                validator_sets_post.get(epoch),
                "Validator set at and after pipeline offset must have changed \
                 - checking epoch {epoch}"
            );
        }

        {
            // TODO: should this loop over epochs after this one as well? Are
            // there any?
            let epoch = pos_params.unbonding_len + 1;
            let expected_stake =
                i128::from(initial_stake) - i128::from(unbond.amount);
            assert_eq!(
                validator_deltas_post.as_ref().unwrap().get(epoch),
                Some(expected_stake),
                "The total deltas at after the unbonding offset epoch must be \
                 decremented by the unbonded amount - checking in epoch: \
                 {epoch}"
            );
            assert_eq!(
                total_deltas_post.get(epoch),
                Some(expected_stake),
                "The total deltas at after the unbonding offset epoch must be \
                 decremented by the unbonded amount - checking in epoch: \
                 {epoch}"
            );
        }

        //     - `#{staking_token}/balance/#{PoS}`
        // Check that PoS account balance is unchanged by unbond
        let pos_balance_post: token::Amount =
            ctx().read(&pos_balance_key)?.unwrap();
        assert_eq!(
            pos_balance_pre, pos_balance_post,
            "Unbonding doesn't affect PoS system balance"
        );

        //     - `#{PoS}/unbond/#{owner}/#{validator}`
        // Check that the unbond doesn't exist until unbonding offset
        let unbonds_post = ctx().read_unbond(&unbond_id)?.unwrap();
        let bonds_post = ctx().read_bond(&unbond_id)?.unwrap();
        for epoch in 0..pos_params.unbonding_len {
            let unbond: Option<Unbond<token::Amount>> = unbonds_post.get(epoch);

            assert!(
                unbond.is_none(),
                "There should be no unbond until unbonding offset - checking \
                 epoch {epoch}"
            );
        }
        // Check that the unbond is as expected
        let start_epoch = match &unbond.source {
            Some(_) => {
                // This bond was a delegation
                namada_tx_prelude::proof_of_stake::types::Epoch::from(
                    pos_params.pipeline_len,
                )
            }
            None => {
                // This bond was a genesis validator self-bond
                namada_tx_prelude::proof_of_stake::types::Epoch::default()
            }
        };
        let end_epoch = namada_tx_prelude::proof_of_stake::types::Epoch::from(
            pos_params.unbonding_len - 1,
        );

        let expected_unbond =
            HashMap::from_iter([((start_epoch, end_epoch), unbond.amount)]);
        let actual_unbond: Unbond<token::Amount> =
            unbonds_post.get(pos_params.unbonding_len).unwrap();
        assert_eq!(
            actual_unbond.deltas, expected_unbond,
            "Delegation at unbonding offset should be equal to the unbonded \
             amount"
        );

        for epoch in pos_params.pipeline_len..pos_params.unbonding_len {
            let bond: Bond<token::Amount> = bonds_post.get(epoch).unwrap();
            let expected_bond =
                HashMap::from_iter([(start_epoch, initial_stake)]);
            assert_eq!(
                bond.pos_deltas, expected_bond,
                "Before unbonding offset, the bond should be untouched, \
                 checking epoch {epoch}"
            );
        }
        {
            // TODO: checl logic here
            let epoch = pos_params.unbonding_len + 1;
            let bond: Bond<token::Amount> = bonds_post.get(epoch).unwrap();
            let expected_bond =
                HashMap::from_iter([(start_epoch, initial_stake)]);
            assert_eq!(
                bond.pos_deltas, expected_bond,
                "At unbonding offset, the pos deltas should not change, \
                 checking epoch {epoch}"
            );
            assert_eq!(
                bond.neg_deltas, unbond.amount,
                "At unbonding offset, the unbonded amount should have been \
                 deducted, checking epoch {epoch}"
            )
        }

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

    fn arb_initial_stake_and_unbond()
    -> impl Strategy<Value = (token::Amount, transaction::pos::Unbond)> {
        // Generate initial stake
        token::testing::arb_amount().prop_flat_map(|initial_stake| {
            // Use the initial stake to limit the bond amount
            let unbond = arb_unbond(u64::from(initial_stake));
            // Use the generated initial stake too too
            (Just(initial_stake), unbond)
        })
    }

    /// Generates an initial validator stake and a unbond, while making sure
    /// that the `initial_stake >= unbond.amount`.
    fn arb_unbond(
        max_amount: u64,
    ) -> impl Strategy<Value = transaction::pos::Unbond> {
        (
            address::testing::arb_established_address(),
            prop::option::of(address::testing::arb_non_internal_address()),
            token::testing::arb_amount_ceiled(max_amount),
        )
            .prop_map(|(validator, source, amount)| {
                let validator = Address::Established(validator);
                transaction::pos::Unbond {
                    validator,
                    amount,
                    source,
                }
            })
    }
}
