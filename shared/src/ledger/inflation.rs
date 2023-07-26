//! General inflation system that will be used to process rewards for
//! proof-of-stake, providing liquity to shielded asset pools, and public goods
//! funding.

use namada_core::types::dec::Dec;

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
    pub locked_ratio: Dec,
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
    pub locked_ratio_target: Dec,
    /// PD last locked ratio
    pub locked_ratio_last: Dec,
    /// Maximum reward rate
    pub max_reward_rate: Dec,
    /// Last inflation amount
    pub last_inflation_amount: token::Amount,
    /// Nominal proportional gain
    pub p_gain_nom: Dec,
    /// Nominal derivative gain
    pub d_gain_nom: Dec,
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

        // Token amounts must be expressed in terms of the raw amount (namnam)
        // to properly run the PD controller
        let locked = Dec::try_from(locked_tokens.raw_amount())
            .expect("Should not fail to convert token Amount to Dec");
        let total = Dec::try_from(total_tokens.raw_amount())
            .expect("Should not fail to convert token Amount to Dec");
        let epochs_py: Dec = epochs_per_year.into();

        let locked_ratio = locked / total;
        let max_inflation = total * max_reward_rate / epochs_py;
        let p_gain = p_gain_nom * max_inflation;
        let d_gain = d_gain_nom * max_inflation;

        let error = locked_ratio_target - locked_ratio;
        let delta_error = locked_ratio_last - locked_ratio;
        let control_val = p_gain * error - d_gain * delta_error;

        let control_val = token::Amount::from_uint(
            control_val
                .to_uint()
                .expect("Should not fail to convert Dec to Uint"),
            0,
        )
        .expect("Should not fail to convert Uint to Amount");

        let max_inflation = token::Amount::from_uint(
            max_inflation
                .to_uint()
                .expect("Should not fail to convert Dec to Uint"),
            0,
        )
        .expect("Should not fail to convert Uint to Amount");

        let new_inflation_amount = last_inflation_amount + control_val;

        let inflation = std::cmp::min(new_inflation_amount, max_inflation);
        ValsToUpdate {
            locked_ratio,
            inflation,
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use namada_core::types::token::NATIVE_MAX_DECIMAL_PLACES;

    use super::*;

    #[test]
    fn test_inflation_calc_up() {
        let mut controller = RewardsController {
            locked_tokens: token::Amount::from_uint(
                2_000,
                NATIVE_MAX_DECIMAL_PLACES,
            )
            .unwrap(),
            total_tokens: token::Amount::from_uint(
                4_000,
                NATIVE_MAX_DECIMAL_PLACES,
            )
            .unwrap(),
            locked_ratio_target: Dec::from_str("0.66666666").unwrap(),
            locked_ratio_last: Dec::from_str("0.5").unwrap(),
            max_reward_rate: Dec::from_str("0.1").unwrap(),
            last_inflation_amount: token::Amount::zero(),
            p_gain_nom: Dec::from_str("0.1").unwrap(),
            d_gain_nom: Dec::from_str("0.1").unwrap(),
            epochs_per_year: 365,
        };
        dbg!(&controller);

        let ValsToUpdate {
            locked_ratio: locked_ratio_0,
            inflation: inflation_0,
        } = controller.clone().run();
        println!(
            "Round 0: Locked ratio: {locked_ratio_0}, inflation: {}",
            inflation_0.to_string_native()
        );
        assert_eq!(locked_ratio_0, Dec::from_str("0.5").unwrap());
        assert_eq!(inflation_0, token::Amount::from_uint(18_264, 0).unwrap());

        controller.locked_ratio_last = locked_ratio_0;
        controller.last_inflation_amount = inflation_0;
        controller.total_tokens += inflation_0;
        controller.locked_tokens += inflation_0;

        let ValsToUpdate {
            locked_ratio: locked_ratio_1,
            inflation: inflation_1,
        } = controller.clone().run();
        println!(
            "Round 1: Locked ratio: {locked_ratio_1}, inflation: {}",
            inflation_1.to_string_native()
        );
        assert!(locked_ratio_1 > locked_ratio_0);
        assert!(locked_ratio_1 > Dec::from_str("0.5").unwrap());
        assert!(locked_ratio_1 < Dec::from_str("0.51").unwrap());
        assert_eq!(inflation_1, token::Amount::from_uint(36_528, 0).unwrap());

        controller.locked_ratio_last = locked_ratio_1;
        controller.last_inflation_amount = inflation_1;
        controller.total_tokens += inflation_1;
        controller.locked_tokens += inflation_1;

        let ValsToUpdate {
            locked_ratio: locked_ratio_2,
            inflation: inflation_2,
        } = controller.run();
        println!(
            "Round 2: Locked ratio: {locked_ratio_2}, inflation: {}",
            inflation_2.to_string_native()
        );
        assert!(locked_ratio_2 > locked_ratio_1);
        assert!(locked_ratio_2 > Dec::from_str("0.5").unwrap());
        assert!(locked_ratio_2 < Dec::from_str("0.51").unwrap());
        assert_eq!(inflation_2, token::Amount::from_uint(54_792, 0).unwrap());
    }

    #[test]
    fn test_inflation_calc_down() {
        let mut controller = RewardsController {
            locked_tokens: token::Amount::from_uint(
                900,
                NATIVE_MAX_DECIMAL_PLACES,
            )
            .unwrap(),
            total_tokens: token::Amount::from_uint(
                1_000,
                NATIVE_MAX_DECIMAL_PLACES,
            )
            .unwrap(),
            locked_ratio_target: Dec::from_str("0.66666666").unwrap(),
            locked_ratio_last: Dec::from_str("0.9").unwrap(),
            max_reward_rate: Dec::from_str("0.1").unwrap(),
            last_inflation_amount: token::Amount::from_uint(10_000, 0).unwrap(),
            p_gain_nom: Dec::from_str("0.1").unwrap(),
            d_gain_nom: Dec::from_str("0.1").unwrap(),
            epochs_per_year: 365,
        };
        dbg!(&controller);

        let ValsToUpdate {
            locked_ratio: locked_ratio_0,
            inflation: inflation_0,
        } = controller.clone().run();
        println!(
            "Round 0: Locked ratio: {locked_ratio_0}, inflation: {}",
            inflation_0.to_string_native()
        );
        assert_eq!(locked_ratio_0, Dec::from_str("0.9").unwrap());
        assert_eq!(inflation_0, token::Amount::from_uint(3_607, 0).unwrap());

        controller.locked_ratio_last = locked_ratio_0;
        controller.last_inflation_amount = inflation_0;
        controller.total_tokens += inflation_0;
        controller.locked_tokens += inflation_0;

        let ValsToUpdate {
            locked_ratio: locked_ratio_1,
            inflation: inflation_1,
        } = controller.clone().run();
        println!(
            "Round 1: Locked ratio: {locked_ratio_1}, inflation: {}",
            inflation_1.to_string_native()
        );
        assert!(locked_ratio_1 > locked_ratio_0);
        assert!(locked_ratio_1 > Dec::from_str("0.9").unwrap());
        assert!(locked_ratio_1 < Dec::from_str("0.91").unwrap());
        assert_eq!(inflation_1, token::Amount::zero());

        controller.locked_ratio_last = locked_ratio_1;
        controller.last_inflation_amount = inflation_1;
        controller.total_tokens += inflation_1;
        controller.locked_tokens += inflation_1;

        let ValsToUpdate {
            locked_ratio: locked_ratio_2,
            inflation: inflation_2,
        } = controller.run();
        println!(
            "Round 2: Locked ratio: {locked_ratio_2}, inflation: {}",
            inflation_2.to_string_native()
        );
        assert_eq!(locked_ratio_2, locked_ratio_1);
        assert_eq!(inflation_2, token::Amount::zero());
    }
}
