//! General inflation system that will be used to process rewards for proof-of-stake, providing liquity to shielded asset pools, and public goods funding.
//! 
//! TODO: possibly change f64 types to BasisPoints

use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::types::BasisPoints;
use rust_decimal::prelude::Decimal;

/// The domains of inflation
pub enum RewardsType {
    Staking,
    Masp,
    PubGoodsFunding,
}

/// PD controller used to dynamically adjust the rewards rates
pub struct RewardsController {
    locked_tokens: u64,
    total_tokens: u64,
    locked_ratio_target: Decimal,
    locked_ratio_last: Decimal,
    max_reward_rate: Decimal,
    last_reward_rate: Decimal,
    p_gain: Decimal,
    d_gain: Decimal,
    epochs_per_yr: u64,
}

impl RewardsController {
    /// Initialize a new PD controller
    pub fn new(
        locked_tokens: u64,
        total_tokens: u64,
        locked_ratio_target: Decimal,
        locked_ratio_last: Decimal,
        max_reward_rate: Decimal,
        last_reward_rate: Decimal,
        p_gain: Decimal,
        d_gain: Decimal,
        epochs_per_yr: u64,
    ) -> Self {
        Self {
            locked_tokens,
            total_tokens,
            locked_ratio_target,
            locked_ratio_last,
            max_reward_rate,
            last_reward_rate,
            p_gain,
            d_gain,
            epochs_per_yr,
        }
    }

    /// Calculate a new rewards rate
    pub fn get_new_reward_rate(&self) -> Decimal {
        let locked: Decimal = self.locked_tokens.into();
        let total: Decimal = self.total_tokens.into();
        let epochs_py: Decimal = self.epochs_per_yr.into();

        let locked_ratio = locked / total;
        let error_p = self.locked_ratio_target - locked_ratio;
        let error_d = self.locked_ratio_last - locked_ratio;

        let gain_factor = self.max_reward_rate * total / epochs_py;
        let p_gain_new = self.p_gain * gain_factor;
        let d_gain_new = self.d_gain * gain_factor;

        let control_val = p_gain_new * error_p - d_gain_new * error_d;
        let reward_rate =
            match self.last_reward_rate + control_val > self.max_reward_rate {
                true => self.max_reward_rate,
                false => match self.last_reward_rate + control_val > Decimal::new(0, 0) {
                    true => self.last_reward_rate + control_val,
                    false => Decimal::new(0, 0),
                },
            };
        reward_rate
    }

    // TODO: provide way to get the new gain factors to store for use in following epoch.
}
