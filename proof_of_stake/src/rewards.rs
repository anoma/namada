//! PoS rewards

use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use thiserror::Error;

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
    proposer_param: Decimal,
    signer_param: Decimal,
    signing_stake: u64,
    total_stake: u64,
}

impl PosRewardsCalculator {
    /// Instantiate a new PosRewardsCalculator
    pub fn new(
        proposer_param: Decimal,
        signer_param: Decimal,
        signing_stake: u64,
        total_stake: u64,
    ) -> Self {
        Self {
            proposer_param,
            signer_param,
            signing_stake,
            total_stake,
        }
    }

    /// Calculate the reward coefficients
    pub fn get_reward_coeffs(&self) -> Result<PosRewards, RewardsError> {
        // TODO: think about possibility of u64 overflow
        let votes_needed = self.get_min_required_votes();
        dbg!(votes_needed);
        dbg!(self.signing_stake.clone());
        println!("\n");
        if self.signing_stake < votes_needed.into() {
            return Err(RewardsError::InsufficentVotes);
        }

        // Logic for determining the coefficients
        // TODO: error handling to ensure proposer_coeff is > 0?
        let proposer_coeff = self.proposer_param
            * Decimal::from(self.signing_stake - votes_needed)
            / Decimal::from(self.total_stake)
            + dec!(0.01);
        let signer_coeff = self.signer_param;
        let active_val_coeff = dec!(1.0) - proposer_coeff - signer_coeff;

        // let proposer_coeff = dec!(0.2);
        // let signer_coeff = dec!(0.1);
        // let active_val_coeff = dec!(0.7);

        let coeffs = PosRewards {
            proposer_coeff,
            signer_coeff,
            active_val_coeff,
        };

        Ok(coeffs)
    }

    /// Implement as ceiling (2/3) * validator set stake
    fn get_min_required_votes(&self) -> u64 {
        ((2 * self.total_stake) + 3 - 1) / 3
    }

    // /// get struct of the reward coefficients
    // pub fn get_reward_coeffs(&self) -> Result<PosRewards, RewardsError> {
    //     match self.pos_rewards {
    //         Some(rewards) => Ok(rewards),
    //         None => Err(RewardsError::CoeffsNotSet),
    //     }
    // }

    // /// proposer reward
    // pub fn get_proposer_coeff(&self) -> Result<Decimal, RewardsError> {
    //     match self.pos_rewards {
    //         Some(rewards) => Ok(rewards.proposer_coeff),
    //         None => Err(RewardsError::CoeffsNotSet),
    //     }
    // }

    // /// signer reward
    // pub fn get_signer_coeff(&self) -> Result<Decimal, RewardsError> {
    //     match self.pos_rewards {
    //         Some(rewards) => Ok(rewards.signer_coeff),
    //         None => Err(RewardsError::CoeffsNotSet),
    //     }
    // }

    // /// active validator reward
    // pub fn get_active_val_coeff(&self) -> Result<Decimal, RewardsError> {
    //     match self.pos_rewards {
    //         Some(rewards) => Ok(rewards.active_val_coeff),
    //         None => Err(RewardsError::CoeffsNotSet),
    //     }
    // }
}
