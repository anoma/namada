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

    ctx.unbond_tokens_new(
        unbond.source.as_ref(),
        &unbond.validator,
        unbond.amount,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use namada::ledger::pos::{BondId, GenesisValidator, PosParams, PosVP};
    use namada::proof_of_stake::types::{Bond, Unbond, WeightedValidator};
    use namada::proof_of_stake::{
        active_validator_set_handle, bond_handle,
        read_active_validator_set_addresses_with_stake, read_total_stake,
        read_validator_stake, unbond_handle,
    };
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
        dbg!(&initial_stake, &unbond);
        let is_delegation = matches!(
            &unbond.source, Some(source) if *source != unbond.validator);
        println!("\nIS DELEGATION = {}\n", is_delegation);
        println!(
            "\nPIPELINE LEN = {}\nUNBONDING LEN = {}\n",
            pos_params.pipeline_len, pos_params.unbonding_len
        );
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

        let native_token = tx_host_env::with(|tx_env| {
            let native_token = tx_env.storage.native_token.clone();
            if is_delegation {
                let source = unbond.source.as_ref().unwrap();
                tx_env.spawn_accounts([source]);

                // To allow to unbond delegation, there must be a delegation
                // bond first.
                // First, credit the bond's source with the initial stake,
                // before we initialize the bond below
                tx_env.credit_tokens(
                    source,
                    &native_token,
                    None,
                    initial_stake,
                );
            }
            native_token
        });

        // Initialize the delegation if it is the case - unlike genesis
        // validator's self-bond, this happens at pipeline offset
        if is_delegation {
            ctx().bond_tokens_new(
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
            source: unbond_src.clone(),
        };

        let pos_balance_key = token::balance_key(
            &native_token,
            &Address::Internal(InternalAddress::PoS),
        );
        let pos_balance_pre: token::Amount = ctx()
            .read(&pos_balance_key)?
            .expect("PoS must have balance");
        assert_eq!(pos_balance_pre, initial_stake);

        println!(
            "\nDEBUGG CURRENT EPOCH = {}\n",
            ctx().get_block_epoch().unwrap()
        );

        let bond_handle = bond_handle(&unbond_src, &unbond.validator, true);

        let mut epoched_total_stake_pre: Vec<token::Amount> = Vec::new();
        let mut epoched_validator_stake_pre: Vec<token::Amount> = Vec::new();
        let mut epoched_bonds_pre: Vec<Option<token::Amount>> = Vec::new();
        let mut epoched_validator_set_pre: Vec<HashSet<WeightedValidator>> =
            Vec::new();

        for epoch in 0..=pos_params.unbonding_len {
            epoched_total_stake_pre.push(
                read_total_stake(ctx(), &pos_params, Epoch(epoch))?.unwrap(),
            );
            epoched_validator_stake_pre.push(
                read_validator_stake(
                    ctx(),
                    &pos_params,
                    &unbond.validator,
                    Epoch(epoch),
                )?
                .unwrap(),
            );
            epoched_bonds_pre.push(
                bond_handle
                    .get_delta_val(ctx(), Epoch(epoch), &pos_params)?
                    .map(token::Amount::from_change),
            );
            epoched_validator_set_pre.push(
                read_active_validator_set_addresses_with_stake(
                    ctx(),
                    &active_validator_set_handle(),
                    Epoch(epoch),
                )?,
            );
        }

        // let _total_deltas_pre = ctx().read_total_deltas()?;
        // let validator_sets_pre = ctx().read_validator_set()?;
        // let _validator_deltas_pre =
        //     ctx().read_validator_deltas(&unbond.validator)?.unwrap();
        // let bonds_pre = ctx().read_bond(&unbond_id)?.unwrap();
        dbg!(&epoched_bonds_pre);

        // Apply the unbond tx
        apply_tx(ctx(), tx_data)?;
        tx_host_env::commit_tx_and_block(); // Needed until #913 is done

        // Read the data after the tx is executed.
        // The following storage keys should be updated:

        //     - `#{PoS}/validator/#{validator}/deltas`
        //     - `#{PoS}/total_deltas`
        //     - `#{PoS}/validator_set`
        let mut epoched_total_stake_post: Vec<token::Amount> = Vec::new();
        let mut epoched_validator_stake_post: Vec<token::Amount> = Vec::new();
        let mut epoched_bonds_post: Vec<Option<token::Amount>> = Vec::new();
        let mut epoched_validator_set_post: Vec<HashSet<WeightedValidator>> =
            Vec::new();

        for epoch in 0..=pos_params.unbonding_len {
            // epoched_total_stake_post.push(
            //     read_total_stake(ctx(), &pos_params, Epoch(epoch))?.unwrap(),
            // );
            // epoched_validator_stake_post.push(
            //     read_validator_stake(
            //         ctx(),
            //         &pos_params,
            //         &unbond.validator,
            //         Epoch(epoch),
            //     )?
            //     .unwrap(),
            // );
            epoched_bonds_post.push(
                bond_handle
                    .get_delta_val(ctx(), Epoch(epoch), &pos_params)?
                    .map(token::Amount::from_change),
            );
            // epoched_validator_set_post.push(
            //     read_active_validator_set_addresses_with_stake(
            //         ctx(),
            //         &active_validator_set_handle(),
            //         Epoch(epoch),
            //     )?,
            // );
        }
        dbg!(&epoched_bonds_post);

        // let total_deltas_post = ctx().read_total_deltas()?;
        // let validator_deltas_post =
        //     ctx().read_validator_deltas(&unbond.validator)?;
        // let validator_sets_post = ctx().read_validator_set()?;

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
        for epoch in 0..pos_params.pipeline_len {
            assert_eq!(
                read_validator_stake(
                    ctx(),
                    &pos_params,
                    &unbond.validator,
                    Epoch(epoch)
                )?,
                Some(expected_amount_before_pipeline.into()),
                "The validator deltas before the pipeline offset must not \
                 change - checking in epoch: {epoch}"
            );
            assert_eq!(
                read_total_stake(ctx(), &pos_params, Epoch(epoch))?,
                Some(expected_amount_before_pipeline.into()),
                "The total deltas before the pipeline offset must not change \
                 - checking in epoch: {epoch}"
            );
            assert_eq!(
                epoched_validator_set_pre[epoch as usize],
                read_active_validator_set_addresses_with_stake(
                    ctx(),
                    &active_validator_set_handle(),
                    Epoch(epoch),
                )?,
                "Validator set before pipeline offset must not change - \
                 checking epoch {epoch}"
            );
        }

        // At and after pipeline offset, there can be either delegation or
        // self-bond, both of which are initialized to the same `initial_stake`
        for epoch in pos_params.pipeline_len..pos_params.unbonding_len {
            assert_eq!(
                read_validator_stake(
                    ctx(),
                    &pos_params,
                    &unbond.validator,
                    Epoch(epoch)
                )?,
                Some((initial_stake - unbond.amount).into()),
                "The validator deltas at and after the pipeline offset must \
                 have changed - checking in epoch: {epoch}"
            );
            assert_eq!(
                read_total_stake(ctx(), &pos_params, Epoch(epoch))?,
                Some((initial_stake - unbond.amount).into()),
                "The total deltas at and after the pipeline offset must have \
                 changed - checking in epoch: {epoch}"
            );
            assert_ne!(
                epoched_validator_set_pre[epoch as usize],
                read_active_validator_set_addresses_with_stake(
                    ctx(),
                    &active_validator_set_handle(),
                    Epoch(epoch),
                )?,
                "The validator set at and after pipeline offset should have \
                 changed - checking epoch {epoch}"
            );
        }

        {
            let epoch = pos_params.unbonding_len + 1;
            let expected_stake =
                i128::from(initial_stake) - i128::from(unbond.amount);
            assert_eq!(
                read_validator_stake(
                    ctx(),
                    &pos_params,
                    &unbond.validator,
                    Epoch(epoch)
                )?
                .map(|v| v.change()),
                Some(expected_stake),
                "The total deltas at after the unbonding offset epoch must be \
                 decremented by the unbonded amount - checking in epoch: \
                 {epoch}"
            );
            assert_eq!(
                read_total_stake(ctx(), &pos_params, Epoch(epoch))?
                    .map(|v| v.change()),
                Some(expected_stake),
                "The total deltas at after the unbonding offset epoch must be \
                 decremented by the unbonded amount - checking in epoch: \
                 {epoch}"
            );
        }

        println!("SLURMY\n");

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

        // Outer epoch is end (withdrawable), inner epoch is beginning of
        let unbond_handle = unbond_handle(&unbond_src, &unbond.validator);

        // let unbonds_post = ctx().read_unbond(&unbond_id)?.unwrap();
        // let bonds_post = ctx().read_bond(&unbond_id)?.unwrap();

        for epoch in 0..(pos_params.pipeline_len + pos_params.unbonding_len) {
            let unbond = unbond_handle.at(&Epoch(epoch));

            assert!(
                unbond.is_empty(ctx())?,
                "There should be no unbond until unbonding offset - checking \
                 epoch {epoch}"
            );
        }
        let start_epoch = if is_delegation {
            // This bond was a delegation
            Epoch::from(pos_params.pipeline_len)
        } else {
            // This bond was a genesis validator self-bond
            Epoch::default()
        };
        // let end_epoch = Epoch::from(pos_params.unbonding_len - 1);

        // let expected_unbond = if unbond.amount == token::Amount::default() {
        //     HashMap::new()
        // } else {
        //     HashMap::from_iter([((start_epoch, end_epoch), unbond.amount)])
        // };

        // Ensure that the unbond is structured as expected, withdrawable at
        // pipeline + unbonding offsets
        println!("READING THE UNBOND IN WASM TEST\n");
        let actual_unbond_amount = unbond_handle
            .at(&Epoch::from(
                pos_params.pipeline_len + pos_params.unbonding_len,
            ))
            .get(ctx(), &start_epoch)?;
        assert_eq!(
            actual_unbond_amount,
            Some(unbond.amount),
            "Delegation at pipeline + unbonding offset should be equal to the \
             unbonded amount"
        );

        for epoch in
            start_epoch.0..(pos_params.pipeline_len + pos_params.unbonding_len)
        {
            let bond_amount =
                bond_handle.get_sum(ctx(), Epoch(epoch), &pos_params)?;

            let expected_amount = initial_stake - unbond.amount;
            assert_eq!(
                bond_amount,
                Some(expected_amount.change()),
                "After the tx is applied, the bond should be changed in \
                 place, checking epoch {epoch}"
            );
        }
        // {
        //     let epoch = pos_params.unbonding_len + 1;
        //     let bond: Bond = bonds_post.get(epoch).unwrap();
        //     let expected_bond =
        //         HashMap::from_iter([(start_epoch, initial_stake)]);
        //     assert_eq!(
        //         bond.pos_deltas, expected_bond,
        //         "At unbonding offset, the pos deltas should not change, \
        //          checking epoch {epoch}"
        //     );
        //     assert_eq!(
        //         bond.neg_deltas, unbond.amount,
        //         "At unbonding offset, the unbonded amount should have been \
        //          deducted, checking epoch {epoch}"
        //     )
        // }

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
        token::testing::arb_amount_ceiled((i64::MAX / 8) as u64).prop_flat_map(
            |initial_stake| {
                // Use the initial stake to limit the bond amount
                let unbond = arb_unbond(u64::from(initial_stake));
                // Use the generated initial stake too too
                (Just(initial_stake), unbond)
            },
        )
    }

    /// Generates an initial validator stake and a unbond, while making sure
    /// that the `initial_stake >= unbond.amount`.
    fn arb_unbond(
        max_amount: u64,
    ) -> impl Strategy<Value = transaction::pos::Unbond> {
        (
            address::testing::arb_established_address(),
            prop::option::of(address::testing::arb_non_internal_address()),
            token::testing::arb_amount_non_zero_ceiled(max_amount),
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
