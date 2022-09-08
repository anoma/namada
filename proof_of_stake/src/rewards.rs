//! PoS rewards

use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use thiserror::Error;

use crate::types::VotingPower;

/// Errors during rewards calculation
#[derive(Debug, Error)]
pub enum RewardsError {
    /// number of votes is less than the threshold of 2/3
    #[error(
        "Insufficient votes, needed at least 2/3 of the total bonded stake"
    )]
    InsufficentVotes,
    /// rewards coefficients are not set
    #[error("Rewards coefficients are not properly set.")]
    CoeffsNotSet,
}

/// Three different ways to get PoS rewards
#[derive(Debug, Copy, Clone)]
pub struct PosRewards {
    proposer_coeff: Decimal,
    signer_coeff: Decimal,
    active_val_coeff: Decimal,
}

/// bing
#[derive(Debug, Copy, Clone)]
pub struct PosRewardsCalculator {
    signing_stake: VotingPower,
    total_stake: VotingPower,
    proposer_param: Decimal,
    signer_param: Decimal,
    pos_rewards: Option<PosRewards>,
}

impl PosRewardsCalculator {
    /// new
    pub fn new(
        signing_stake: VotingPower,
        total_stake: VotingPower,
        proposer_param: Decimal,
        signer_param: Decimal,
    ) -> Self {
        Self {
            proposer_param,
            signer_param,
            signing_stake,
            total_stake,
            pos_rewards: None,
        }
    }

    /// descr
    pub fn set_reward_coeffs(&mut self) -> Result<(), RewardsError> {
        // TODO: think about possibility of u64 overflow
        let votes_needed = self.get_min_required_votes();
        if self.signing_stake < votes_needed.into() {
            return Err(RewardsError::InsufficentVotes);
        }

        // Logic for determining the coefficients (WIP WIP WIP)
        let proposer_coeff: Decimal = (self.proposer_param
            * (u64::from(self.signing_stake) - votes_needed))
            .into();
        let signer_coeff: Decimal = self.signer_param.into();
        let active_val_coeff =
            Decimal::new(1, 0) - proposer_coeff - signer_coeff;

        self.pos_rewards = Some(PosRewards {
            proposer_coeff,
            signer_coeff,
            active_val_coeff,
        });

        Ok(())
    }

    /// Implement as ceiling (2/3) * validator set size
    fn get_min_required_votes(&self) -> u64 {
        let num = 2 * u64::from(self.total_stake);
        (num + 3 - 1) / 3
    }

    /// get struct of the reward coefficients
    pub fn get_reward_coeffs(&self) -> Result<PosRewards, RewardsError> {
        match self.pos_rewards {
            Some(rewards) => Ok(rewards),
            None => Err(RewardsError::CoeffsNotSet),
        }
    }

    /// proposer reward
    pub fn get_proposer_coeff(&self) -> Result<Decimal, RewardsError> {
        match self.pos_rewards {
            Some(rewards) => Ok(rewards.proposer_coeff),
            None => Err(RewardsError::CoeffsNotSet),
        }
    }

    /// signer reward
    pub fn get_signer_coeff(&self) -> Result<Decimal, RewardsError> {
        match self.pos_rewards {
            Some(rewards) => Ok(rewards.signer_coeff),
            None => Err(RewardsError::CoeffsNotSet),
        }
    }

    /// active validator reward
    pub fn get_active_val_coeff(&self) -> Result<Decimal, RewardsError> {
        match self.pos_rewards {
            Some(rewards) => Ok(rewards.active_val_coeff),
            None => Err(RewardsError::CoeffsNotSet),
        }
    }
}
