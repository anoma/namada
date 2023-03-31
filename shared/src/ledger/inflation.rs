//! General inflation system that will be used to process rewards for
//! proof-of-stake, providing liquity to shielded asset pools, and public goods
//! funding.

use rust_decimal::Decimal;
use rust_decimal_macros::dec;

use crate::types::token;

/// The domains of inflation
pub enum RewardsType {
    /// Proof-of-stake rewards
    Staking,
    /// Rewards for locking tokens in the multi-asset shielded pool
    Masp,
    /// Rewards for public goods funding (PGF)
    PubGoodsFunding,
}

/// Holds the PD controller values that should be updated in storage
#[allow(missing_docs)]
pub struct ValsToUpdate {
    pub locked_ratio: Decimal,
    pub inflation: token::Amount,
}

/// PD controller used to dynamically adjust the rewards rates
#[derive(Debug, Clone)]
pub struct RewardsController {
    /// Locked token amount in the relevant system
    pub locked_tokens: token::Amount,
    /// Total token supply
    pub total_tokens: token::Amount,
    /// PD target locked ratio
    pub locked_ratio_target: Decimal,
    /// PD last locked ratio
    pub locked_ratio_last: Decimal,
    /// Maximum reward rate
    pub max_reward_rate: Decimal,
    /// Last inflation amount
    pub last_inflation_amount: token::Amount,
    /// Nominal proportional gain
    pub p_gain_nom: Decimal,
    /// Nominal derivative gain
    pub d_gain_nom: Decimal,
    /// Number of epochs per year
    pub epochs_per_year: u64,
}

impl RewardsController {
    /// Calculate a new rewards rate
    pub fn run(self) -> ValsToUpdate {
        let Self {
            locked_tokens,
            total_tokens,
            locked_ratio_target,
            locked_ratio_last,
            max_reward_rate,
            last_inflation_amount,
            p_gain_nom,
            d_gain_nom,
            epochs_per_year,
        } = self;

        let locked: Decimal = locked_tokens.as_dec_unscaled();
        let total: Decimal = total_tokens.as_dec_unscaled();
        let epochs_py: Decimal = epochs_per_year.into();

        let locked_ratio = locked / total;
        let max_inflation = total * max_reward_rate / epochs_py;
        let p_gain = p_gain_nom * max_inflation;
        let d_gain = d_gain_nom * max_inflation;

        let error = locked_ratio_target - locked_ratio;
        let delta_error = locked_ratio_last - locked_ratio;
        let control_val = p_gain * error - d_gain * delta_error;

        let last_inflation_amount = last_inflation_amount.as_dec_unscaled();
        let inflation = if last_inflation_amount + control_val > max_inflation {
            max_inflation
        } else if last_inflation_amount + control_val > dec!(0.0) {
            last_inflation_amount + control_val
        } else {
            dec!(0.0)
        };
        let inflation = token::Amount::from_dec_unscaled(inflation);

        ValsToUpdate {
            locked_ratio,
            inflation,
        }
    }
}
