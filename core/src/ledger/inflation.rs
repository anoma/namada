//! General inflation system that will be used to process rewards for
//! proof-of-stake, providing liquity to shielded asset pools, and public goods
//! funding.

use crate::types::dec::Dec;
use crate::types::uint::Uint;

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
    pub inflation: Uint,
}

/// PD controller used to dynamically adjust the rewards rates
#[derive(Debug, Clone)]
pub struct RewardsController {
    /// Locked token amount in the relevant system
    pub locked_tokens: Uint,
    /// Total token supply
    pub total_tokens: Uint,
    /// Total native token supply
    pub total_native_tokens: Uint,
    /// PD target locked ratio
    pub locked_ratio_target: Dec,
    /// PD last locked ratio
    pub locked_ratio_last: Dec,
    /// Maximum reward rate
    pub max_reward_rate: Dec,
    /// Last inflation amount
    pub last_inflation_amount: Uint,
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
            total_native_tokens,
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
        let locked = Dec::try_from(locked_tokens)
            .expect("Should not fail to convert Uint to Dec");
        let total = Dec::try_from(total_tokens)
            .expect("Should not fail to convert Uint to Dec");
        let total_native = Dec::try_from(total_native_tokens)
            .expect("Should not fail to convert Uint to Dec");
        let epochs_py: Dec = epochs_per_year.into();

        let locked_ratio = if total.is_zero() {
            Dec::one()
        } else {
            locked / total
        };
        let max_inflation = total_native * max_reward_rate / epochs_py;
        let p_gain = p_gain_nom * max_inflation;
        let d_gain = d_gain_nom * max_inflation;

        let error = locked_ratio_target - locked_ratio;
        let delta_error = locked_ratio_last - locked_ratio;
        let control_val = p_gain * error - d_gain * delta_error;

        let last_inflation_amount = Dec::try_from(last_inflation_amount)
            .expect("Should not fail to convert Uint to Dec");
        let new_inflation_amount_raw = last_inflation_amount + control_val;
        let new_inflation_amount = if new_inflation_amount_raw.is_negative() {
            Uint::zero()
        } else {
            new_inflation_amount_raw
                .to_uint()
                .expect("Should not fail to convert Dec to Uint")
        };

        let max_inflation = max_inflation
            .to_uint()
            .expect("Should not fail to convert Dec to Uint");

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

    use super::*;

    #[test]
    fn test_inflation_calc_up() {
        let mut controller = RewardsController {
            locked_tokens: Uint::from(2_000_000_000),
            total_tokens: Uint::from(4_000_000_000_u64),
            total_native_tokens: Uint::from(4_000_000_000_u64),
            locked_ratio_target: Dec::from_str("0.66666666").unwrap(),
            locked_ratio_last: Dec::from_str("0.5").unwrap(),
            max_reward_rate: Dec::from_str("0.1").unwrap(),
            last_inflation_amount: Uint::zero(),
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
            "Round 0: Locked ratio: {locked_ratio_0}, inflation: {inflation_0}"
        );
        assert_eq!(locked_ratio_0, Dec::from_str("0.5").unwrap());
        assert_eq!(inflation_0, Uint::from(18_264));

        controller.locked_ratio_last = locked_ratio_0;
        controller.last_inflation_amount = inflation_0;
        controller.total_tokens += inflation_0;
        controller.locked_tokens += inflation_0;

        let ValsToUpdate {
            locked_ratio: locked_ratio_1,
            inflation: inflation_1,
        } = controller.clone().run();
        println!(
            "Round 1: Locked ratio: {locked_ratio_1}, inflation: {inflation_1}"
        );
        assert!(locked_ratio_1 > locked_ratio_0);
        assert!(locked_ratio_1 > Dec::from_str("0.5").unwrap());
        assert!(locked_ratio_1 < Dec::from_str("0.51").unwrap());
        assert_eq!(inflation_1, Uint::from(36_528));

        controller.locked_ratio_last = locked_ratio_1;
        controller.last_inflation_amount = inflation_1;
        controller.total_tokens += inflation_1;
        controller.locked_tokens += inflation_1;

        let ValsToUpdate {
            locked_ratio: locked_ratio_2,
            inflation: inflation_2,
        } = controller.run();
        println!(
            "Round 2: Locked ratio: {locked_ratio_2}, inflation: {inflation_2}",
        );
        assert!(locked_ratio_2 > locked_ratio_1);
        assert!(locked_ratio_2 > Dec::from_str("0.5").unwrap());
        assert!(locked_ratio_2 < Dec::from_str("0.51").unwrap());
        assert_eq!(inflation_2, Uint::from(54_792));
    }

    #[test]
    fn test_inflation_calc_down() {
        let mut controller = RewardsController {
            locked_tokens: Uint::from(900_000_000),
            total_tokens: Uint::from(1_000_000_000),
            total_native_tokens: Uint::from(1_000_000_000),
            locked_ratio_target: Dec::from_str("0.66666666").unwrap(),
            locked_ratio_last: Dec::from_str("0.9").unwrap(),
            max_reward_rate: Dec::from_str("0.1").unwrap(),
            last_inflation_amount: Uint::from(10_000),
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
            "Round 0: Locked ratio: {locked_ratio_0}, inflation: {inflation_0}",
        );
        assert_eq!(locked_ratio_0, Dec::from_str("0.9").unwrap());
        assert_eq!(inflation_0, Uint::from(3_607));

        controller.locked_ratio_last = locked_ratio_0;
        controller.last_inflation_amount = inflation_0;
        controller.total_tokens += inflation_0;
        controller.locked_tokens += inflation_0;

        let ValsToUpdate {
            locked_ratio: locked_ratio_1,
            inflation: inflation_1,
        } = controller.clone().run();
        println!(
            "Round 1: Locked ratio: {locked_ratio_1}, inflation: {inflation_1}",
        );
        assert!(locked_ratio_1 > locked_ratio_0);
        assert!(locked_ratio_1 > Dec::from_str("0.9").unwrap());
        assert!(locked_ratio_1 < Dec::from_str("0.91").unwrap());
        assert_eq!(inflation_1, Uint::zero());

        controller.locked_ratio_last = locked_ratio_1;
        controller.last_inflation_amount = inflation_1;
        controller.total_tokens += inflation_1;
        controller.locked_tokens += inflation_1;

        let ValsToUpdate {
            locked_ratio: locked_ratio_2,
            inflation: inflation_2,
        } = controller.run();
        println!(
            "Round 2: Locked ratio: {locked_ratio_2}, inflation: {inflation_2}",
        );
        assert_eq!(locked_ratio_2, locked_ratio_1);
        assert_eq!(inflation_2, Uint::zero());
    }
}
