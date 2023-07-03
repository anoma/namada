//! PoS rewards distribution.

use namada_core::types::dec::Dec;
use namada_core::types::token::Amount;
use namada_core::types::uint::{Uint, I256};
use thiserror::Error;

/// This is equal to 0.01.
const MIN_PROPOSER_REWARD: Dec =
    Dec(I256(Uint([10000000000u64, 0u64, 0u64, 0u64])));

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
        votes_needed: Uint,
        signing_stake: Uint,
    },
    /// rewards coefficients are not set
    #[error("Rewards coefficients are not properly set.")]
    CoeffsNotSet,
}

/// Holds coefficients for the three different ways to get PoS rewards
#[derive(Debug, Copy, Clone)]
#[allow(missing_docs)]
pub struct PosRewards {
    pub proposer_coeff: Dec,
    pub signer_coeff: Dec,
    pub active_val_coeff: Dec,
}

/// Holds relevant PoS parameters and is used to calculate the coefficients for
/// the rewards
#[derive(Debug, Copy, Clone)]
pub struct PosRewardsCalculator {
    /// Rewards fraction that goes to the block proposer
    pub proposer_reward: Dec,
    /// Rewards fraction that goes to the block signers
    pub signer_reward: Dec,
    /// Total stake of validators who signed the block
    pub signing_stake: Amount,
    /// Total stake of the whole consensus set
    pub total_stake: Amount,
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
                votes_needed: votes_needed.into(),
                signing_stake: signing_stake.into(),
            });
        }

        // Logic for determining the coefficients.
        let proposer_coeff =
            Dec::from(proposer_reward * (signing_stake - votes_needed))
                / Dec::from(total_stake)
                + MIN_PROPOSER_REWARD;
        let signer_coeff = signer_reward;
        let active_val_coeff = Dec::one() - proposer_coeff - signer_coeff;

        let coeffs = PosRewards {
            proposer_coeff,
            signer_coeff,
            active_val_coeff,
        };

        Ok(coeffs)
    }

    /// Implement as ceiling of (2/3) * validator set stake
    fn get_min_required_votes(&self) -> Amount {
        ((self.total_stake * 2u64) + (3u64 - 1u64)) / 3u64
    }
}
