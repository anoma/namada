//! Proof-of-Stake system parameters

use borsh::{BorshDeserialize, BorshSerialize};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use thiserror::Error;

/// Proof-of-Stake system parameters, set at genesis and can only be changed via
/// governance
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct PosParams {
    /// A maximum number of consensus validators
    pub max_validator_slots: u64,
    /// Any change applied during an epoch `n` will become active at the
    /// beginning of epoch `n + pipeline_len`.
    pub pipeline_len: u64,
    /// How many epochs after a committed fault a validator can be slashed.
    /// If a fault is detected in epoch `n`, it can slashed up until the end of
    /// `n + slashable_period_len` epoch.
    /// The value must be greater or equal to `pipeline_len`.
    pub unbonding_len: u64,
    /// The voting power per fundamental unit of the staking token (namnam).
    /// Used in validators' voting power calculation to interface with
    /// tendermint.
    pub tm_votes_per_token: Decimal,
    /// Amount of tokens rewarded to a validator for proposing a block
    pub block_proposer_reward: Decimal,
    /// Amount of tokens rewarded to each validator that voted on a block
    /// proposal
    pub block_vote_reward: Decimal,
    /// Maximum staking rewards rate per annum
    pub max_inflation_rate: Decimal,
    /// Target ratio of staked NAM tokens to total NAM tokens
    pub target_staked_ratio: Decimal,
    /// Fraction of validator's stake that should be slashed on a duplicate
    /// vote.
    pub duplicate_vote_min_slash_rate: Decimal,
    /// Fraction of validator's stake that should be slashed on a light client
    /// attack.
    pub light_client_attack_min_slash_rate: Decimal,
}

impl Default for PosParams {
    fn default() -> Self {
        Self {
            max_validator_slots: 100,
            pipeline_len: 2,
            unbonding_len: 21,
            // 1 voting power per 1 fundamental token (10^6 per NAM or 1 per
            // namnam)
            tm_votes_per_token: dec!(1.0),
            block_proposer_reward: dec!(0.125),
            block_vote_reward: dec!(0.1),
            // PoS inflation of 10%
            max_inflation_rate: dec!(0.1),
            // target staked ratio of 2/3
            target_staked_ratio: dec!(0.6667),
            // slash 0.1%
            duplicate_vote_min_slash_rate: dec!(0.001),
            // slash 0.1%
            light_client_attack_min_slash_rate: dec!(0.001),
        }
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error(
        "Maximum total voting power is too large: got {0}, expected at most \
         {MAX_TOTAL_VOTING_POWER}"
    )]
    TotalVotingPowerTooLarge(u64),
    #[error("Votes per token cannot be greater than 1, got {0}")]
    VotesPerTokenGreaterThanOne(Decimal),
    #[error("Pipeline length must be >= 2, got {0}")]
    PipelineLenTooShort(u64),
    #[error(
        "Unbonding length must be > pipeline length. Got unbonding: {0}, \
         pipeline: {1}"
    )]
    UnbondingLenTooShort(u64, u64),
}

/// The number of fundamental units per whole token of the native staking token
pub const TOKENS_PER_NAM: u64 = 1_000_000;

/// From Tendermint: <https://github.com/tendermint/tendermint/blob/master/spec/abci/apps.md#updating-the-validator-set>
const MAX_TOTAL_VOTING_POWER: i64 = i64::MAX / 8;

/// Assuming token amount is `u64` in micro units.
const TOKEN_MAX_AMOUNT: u64 = u64::MAX / TOKENS_PER_NAM;

impl PosParams {
    /// Validate PoS parameters values. Returns an empty list if the values are
    /// valid.
    #[must_use]
    pub fn validate(&self) -> Vec<ValidationError> {
        let mut errors = vec![];

        if self.pipeline_len < 2 {
            errors
                .push(ValidationError::PipelineLenTooShort(self.pipeline_len));
        }

        if self.pipeline_len >= self.unbonding_len {
            errors.push(ValidationError::UnbondingLenTooShort(
                self.unbonding_len,
                self.pipeline_len,
            ))
        }

        // Check maximum total voting power cannot get larger than what
        // Tendermint allows
        //
        // TODO: decide if this is still a check we want to do (in its current
        // state with our latest voting power conventions, it will fail
        // always)
        let max_total_voting_power = Decimal::from(self.max_validator_slots)
            * self.tm_votes_per_token
            * Decimal::from(TOKEN_MAX_AMOUNT);
        match i64::try_from(max_total_voting_power) {
            Ok(max_total_voting_power_i64) => {
                if max_total_voting_power_i64 > MAX_TOTAL_VOTING_POWER {
                    errors.push(ValidationError::TotalVotingPowerTooLarge(
                        max_total_voting_power.to_u64().unwrap(),
                    ))
                }
            }
            Err(_) => errors.push(ValidationError::TotalVotingPowerTooLarge(
                max_total_voting_power.to_u64().unwrap(),
            )),
        }

        // Check that there is no more than 1 vote per token
        if self.tm_votes_per_token > dec!(1.0) {
            errors.push(ValidationError::VotesPerTokenGreaterThanOne(
                self.tm_votes_per_token,
            ))
        }

        errors
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use testing::arb_pos_params;

    use super::*;

    proptest! {
        #[test]
        fn test_validate_arb_pos_params(pos_params in arb_pos_params(None)) {
            let errors = pos_params.validate();
            assert!(
                errors.is_empty(),
                "Arbitrary PoS parameters must be valid, `validate()` failed. \
                Parameters {:#?}\nErrors: {:#?}",
                pos_params,
                errors
            );
        }
    }
}

/// Testing helpers
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use proptest::prelude::*;
    use rust_decimal::Decimal;

    use super::*;

    prop_compose! {
        /// Generate arbitrary valid ([`PosParams::validate`]) PoS parameters.
        pub fn arb_pos_params(num_max_validator_slots: Option<u64>)
            (pipeline_len in 2..8_u64)
            (max_validator_slots in 1..num_max_validator_slots.unwrap_or(128),
            // `unbonding_len` > `pipeline_len`
            unbonding_len in pipeline_len + 1..pipeline_len + 8,
            pipeline_len in Just(pipeline_len),
            tm_votes_per_token in 1..10_001_u64)
            -> PosParams {
            PosParams {
                max_validator_slots,
                pipeline_len,
                unbonding_len,
                tm_votes_per_token: Decimal::from(tm_votes_per_token) / dec!(10_000),
                // The rest of the parameters that are not being used in the PoS
                // VP are constant for now
                ..Default::default()
            }
        }
    }

    /// Get an arbitrary rate - a Decimal value between 0 and 1 inclusive, with
    /// some fixed precision
    pub fn arb_rate() -> impl Strategy<Value = Decimal> {
        (0..=100_000_u64)
            .prop_map(|num| Decimal::from(num) / Decimal::from(100_000_u64))
    }
}
