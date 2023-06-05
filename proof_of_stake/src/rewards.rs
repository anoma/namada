//! PoS rewards distribution.

use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use thiserror::Error;

const MIN_PROPOSER_REWARD: Decimal = dec!(0.01);

/// Errors during rewards calculation
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum RewardsError {
    /// number of votes is less than the threshold of 2/3
    #[error(
        "Insufficient votes. Got {signing_stake}, needed {votes_needed} (at \
         least 2/3 of the total bonded stake)."
    )]
    InsufficientVotes {
        votes_needed: u64,
        signing_stake: u64,
    },
    /// rewards coefficients are not set
    #[error("Rewards coefficients are not properly set.")]
    CoeffsNotSet,
}

/// Holds coefficients for the three different ways to get PoS rewards
#[derive(Debug, Copy, Clone)]
#[allow(missing_docs)]
pub struct PosRewards {
    pub proposer_coeff: Decimal,
    pub signer_coeff: Decimal,
    pub active_val_coeff: Decimal,
}

/// Holds relevant PoS parameters and is used to calculate the coefficients for
/// the rewards
#[derive(Debug, Copy, Clone)]
pub struct PosRewardsCalculator {
    /// Rewards fraction that goes to the block proposer
    pub proposer_reward: Decimal,
    /// Rewards fraction that goes to the block signers
    pub signer_reward: Decimal,
    /// Total stake of validators who signed the block
    pub signing_stake: u64,
    /// Total stake of the whole consensus set
    pub total_stake: u64,
}

impl PosRewardsCalculator {
    /// Calculate the rewards coefficients. These are used in combination with
    /// the validator's signing behavior and stake to determine the fraction of
    /// the block rewards earned.
    pub fn get_reward_coeffs(&self) -> Result<PosRewards, RewardsError> {
        // TODO: think about possibility of u64 overflow
        let votes_needed = self.get_min_required_votes();

        let Self {
            proposer_reward,
            signer_reward,
            signing_stake,
            total_stake,
        } = *self;

        if signing_stake < votes_needed {
            return Err(RewardsError::InsufficientVotes {
                votes_needed,
                signing_stake,
            });
        }

        // Logic for determining the coefficients.
        let proposer_coeff = proposer_reward
            * Decimal::from(signing_stake - votes_needed)
            / Decimal::from(total_stake)
            + MIN_PROPOSER_REWARD;
        let signer_coeff = signer_reward;
        let active_val_coeff = dec!(1.0) - proposer_coeff - signer_coeff;

        let coeffs = PosRewards {
            proposer_coeff,
            signer_coeff,
            active_val_coeff,
        };

        Ok(coeffs)
    }

    /// Implement as ceiling of (2/3) * validator set stake
    fn get_min_required_votes(&self) -> u64 {
        ((2 * self.total_stake) + 3 - 1) / 3
    }
}
