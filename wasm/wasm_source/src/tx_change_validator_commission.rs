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
        .wrap_err("failed to decode Decimal value")?;
    ctx.change_validator_commission_rate(&validator, &new_rate)
}

#[cfg(test)]
mod tests {
    use std::cmp;

    use namada::ledger::pos::{PosParams, PosVP};
    use namada::proto::Tx;
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
    use namada_vp_prelude::proof_of_stake::{
        CommissionRates, GenesisValidator,
    };
    use proptest::prelude::*;
    use rust_decimal::prelude::ToPrimitive;
    use rust_decimal::Decimal;

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
            pos_params in arb_pos_params()) {
            test_tx_change_validator_commission_aux(commission_state_change.2, commission_state_change.0, commission_state_change.1, key, pos_params).unwrap()
        }
    }

    fn test_tx_change_validator_commission_aux(
        commission_change: transaction::pos::CommissionChange,
        initial_rate: Decimal,
        max_change: Decimal,
        key: key::common::SecretKey,
        pos_params: PosParams,
    ) -> TxResult {
        let consensus_key = key::testing::keypair_1().ref_to();
        let genesis_validators = [GenesisValidator {
            address: commission_change.validator.clone(),
            tokens: token::Amount::from(1_000_000),
            consensus_key,
            commission_rate: initial_rate,
            max_commission_rate_change: max_change,
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        let tx_code = vec![];
        let tx_data = commission_change.try_to_vec().unwrap();
        let tx = Tx::new(tx_code, Some(tx_data));
        let signed_tx = tx.sign(&key);
        let tx_data = signed_tx.data.unwrap();

        // Read the data before the tx is executed
        let commission_rates_pre: CommissionRates = ctx()
            .read_validator_commission_rate(&commission_change.validator)?
            .expect("PoS validator must have commission rates");
        let commission_rate = *commission_rates_pre
            .get(0)
            .expect("PoS validator must have commission rate at genesis");
        assert_eq!(commission_rate, initial_rate);

        apply_tx(ctx(), tx_data)?;

        // Read the data after the tx is executed

        // The following storage keys should be updated:

        //     - `#{PoS}/validator/#{validator}/commission_rate`

        let commission_rates_post: CommissionRates = ctx()
            .read_validator_commission_rate(&commission_change.validator)?
            .unwrap();

        dbg!(&commission_rates_pre);
        dbg!(&commission_rates_post);

        // Before pipeline, the commission rates should not change
        for epoch in 0..pos_params.pipeline_len {
            assert_eq!(
                commission_rates_pre.get(epoch),
                commission_rates_post.get(epoch),
                "The commission rates before the pipeline offset must not \
                 change - checking in epoch: {epoch}"
            );
            assert_eq!(
                Some(&initial_rate),
                commission_rates_post.get(epoch),
                "The commission rates before the pipeline offset must not \
                 change - checking in epoch: {epoch}"
            );
        }

        // After pipeline, the commission rates should have changed
        for epoch in pos_params.pipeline_len..=pos_params.unbonding_len {
            assert_ne!(
                commission_rates_pre.get(epoch),
                commission_rates_post.get(epoch),
                "The commission rate after the pipeline offset must have \
                 changed - checking in epoch: {epoch}"
            );
            assert_eq!(
                Some(&commission_change.new_rate),
                commission_rates_post.get(epoch),
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

    fn arb_rate(min: Decimal, max: Decimal) -> impl Strategy<Value = Decimal> {
        let int_min: u64 = (min * Decimal::from(100_000_u64))
            .to_u64()
            .unwrap_or_default();
        let int_max: u64 = (max * Decimal::from(100_000_u64)).to_u64().unwrap();
        (int_min..=int_max)
            .prop_map(|num| Decimal::from(num) / Decimal::from(100_000_u64))
    }

    fn arb_new_rate(
        min: Decimal,
        max: Decimal,
        rate_pre: Decimal,
    ) -> impl Strategy<Value = Decimal> {
        arb_rate(min, max).prop_filter(
            "New rate must not be equal to the previous epoch's rate",
            move |v| v != &rate_pre,
        )
    }

    fn arb_commission_change(
        rate_pre: Decimal,
        max_change: Decimal,
    ) -> impl Strategy<Value = transaction::pos::CommissionChange> {
        let min = cmp::max(rate_pre - max_change, Decimal::ZERO);
        let max = cmp::min(rate_pre + max_change, Decimal::ONE);
        (arb_established_address(), arb_new_rate(min, max, rate_pre)).prop_map(
            |(validator, new_rate)| transaction::pos::CommissionChange {
                validator: Address::Established(validator),
                new_rate,
            },
        )
    }

    fn arb_commission_info()
    -> impl Strategy<Value = (Decimal, Decimal, transaction::pos::CommissionChange)>
    {
        let min = Decimal::ZERO;
        let max = Decimal::ONE;
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
