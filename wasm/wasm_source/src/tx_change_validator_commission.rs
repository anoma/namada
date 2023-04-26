//! A tx for a validator to change their commission rate for PoS rewards.

use namada_tx_prelude::transaction::pos::CommissionChange;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let CommissionChange {
        validator,
        new_rate,
    } = transaction::pos::CommissionChange::try_from_slice(&data[..])
        .wrap_err("failed to decode Dec value")?;
    ctx.change_validator_commission_rate(&validator, &new_rate)
}

#[cfg(test)]
mod tests {
    use std::cmp;

    use namada::ledger::pos::{PosParams, PosVP};
    use namada::proof_of_stake::validator_commission_rate_handle;
    use namada::proto::Tx;
    use namada::types::chain::ChainId;
    use namada::types::dec::Dec;
    use namada::types::storage::Epoch;
    use namada_tests::log::test;
    use namada_tests::native_vp::pos::init_pos;
    use namada_tests::native_vp::TestNativeVpEnv;
    use namada_tests::tx::*;
    use namada_tx_prelude::address::testing::arb_established_address;
    use namada_tx_prelude::key::testing::arb_common_keypair;
    use namada_tx_prelude::key::RefTo;
    use namada_tx_prelude::proof_of_stake::parameters::testing::arb_pos_params;
    use namada_tx_prelude::token;
    use namada_vp_prelude::proof_of_stake::GenesisValidator;
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// In this test we setup the ledger and PoS system with an arbitrary
        /// initial state with 1 genesis validator and arbitrary PoS parameters. We then
        /// generate an arbitrary bond that we'd like to apply.
        ///
        /// After we apply the bond, we check that all the storage values
        /// in PoS system have been updated as expected and then we also check
        /// that this transaction is accepted by the PoS validity predicate.
        #[test]
        fn test_tx_change_validator_commissions(
            commission_state_change in arb_commission_info(),
            // A key to sign the transaction
            key in arb_common_keypair(),
            pos_params in arb_pos_params(None)) {
            test_tx_change_validator_commission_aux(commission_state_change.2, commission_state_change.0, commission_state_change.1, key, pos_params).unwrap()
        }
    }

    fn test_tx_change_validator_commission_aux(
        commission_change: transaction::pos::CommissionChange,
        initial_rate: Dec,
        max_change: Dec,
        key: key::common::SecretKey,
        pos_params: PosParams,
    ) -> TxResult {
        let consensus_key = key::testing::keypair_1().ref_to();
        let genesis_validators = [GenesisValidator {
            address: commission_change.validator.clone(),
            tokens: token::Amount::from_uint(1_000_000, 0).unwrap(),
            consensus_key,
            commission_rate: initial_rate,
            max_commission_rate_change: max_change,
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        let tx_code = vec![];
        let tx_data = commission_change.try_to_vec().unwrap();
        let tx = Tx::new(tx_code, Some(tx_data), ChainId::default(), None);
        let signed_tx = tx.sign(&key);
        let tx_data = signed_tx.data.unwrap();

        // Read the data before the tx is executed
        let commission_rate_handle =
            validator_commission_rate_handle(&commission_change.validator);

        let mut commission_rates_pre = Vec::<Option<Dec>>::new();
        for epoch in Epoch::default().iter_range(pos_params.unbonding_len + 1) {
            commission_rates_pre.push(commission_rate_handle.get(
                ctx(),
                epoch,
                &pos_params,
            )?)
        }

        assert_eq!(commission_rates_pre[0], Some(initial_rate));

        apply_tx(ctx(), tx_data)?;

        // Read the data after the tx is executed

        // The following storage keys should be updated:

        //     - `#{PoS}/validator/#{validator}/commission_rate`

        // Before pipeline, the commission rates should not change
        for epoch in 0..pos_params.pipeline_len {
            assert_eq!(
                commission_rates_pre[epoch as usize],
                commission_rate_handle.get(ctx(), Epoch(epoch), &pos_params)?,
                "The commission rates before the pipeline offset must not \
                 change - checking in epoch: {epoch}"
            );
            assert_eq!(
                Some(initial_rate),
                commission_rate_handle.get(ctx(), Epoch(epoch), &pos_params)?,
                "The commission rates before the pipeline offset must not \
                 change - checking in epoch: {epoch}"
            );
        }

        // After pipeline, the commission rates should have changed
        for epoch in pos_params.pipeline_len..=pos_params.unbonding_len {
            assert_ne!(
                commission_rates_pre[epoch as usize],
                commission_rate_handle.get(ctx(), Epoch(epoch), &pos_params)?,
                "The commission rate after the pipeline offset must have \
                 changed - checking in epoch: {epoch}"
            );
            assert_eq!(
                Some(commission_change.new_rate),
                commission_rate_handle.get(ctx(), Epoch(epoch), &pos_params)?,
                "The commission rate after the pipeline offset must be the \
                 new_rate - checking in epoch: {epoch}"
            );
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

    fn arb_rate(min: Dec, max: Dec) -> impl Strategy<Value = Dec> {
        let scale = Dec::new(100_000, 0).expect("Test failed");
        let int_min = (min * scale).to_uint();
        let int_min = u64::try_from(int_min).unwrap();
        let int_max = (max * scale).to_uint();
        let int_max = u64::try_from(int_max).unwrap();
        (int_min..=int_max).prop_map(move |num| Dec::from(num) / scale)
    }

    fn arb_new_rate(
        min: Dec,
        max: Dec,
        rate_pre: Dec,
    ) -> impl Strategy<Value = Dec> {
        arb_rate(min, max).prop_filter(
            "New rate must not be equal to the previous epoch's rate",
            move |v| v != &rate_pre,
        )
    }

    fn arb_commission_change(
        rate_pre: Dec,
        max_change: Dec,
    ) -> impl Strategy<Value = transaction::pos::CommissionChange> {
        let min = cmp::max(rate_pre - max_change, Dec::zero());
        let max = cmp::min(rate_pre + max_change, Dec::one());
        (arb_established_address(), arb_new_rate(min, max, rate_pre)).prop_map(
            |(validator, new_rate)| transaction::pos::CommissionChange {
                validator: Address::Established(validator),
                new_rate,
            },
        )
    }

    fn arb_commission_info()
    -> impl Strategy<Value = (Dec, Dec, transaction::pos::CommissionChange)>
    {
        let min = Dec::zero();
        let max = Dec::one();
        (arb_rate(min, max), arb_rate(min, max)).prop_flat_map(
            |(rate, change)| {
                (
                    Just(rate),
                    Just(change),
                    arb_commission_change(rate, change),
                )
            },
        )
    }
}
