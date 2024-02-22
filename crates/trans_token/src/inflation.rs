//! General inflation system that will be used to process rewards for
//! proof-of-stake, providing liquity to shielded asset pools, and public goods
//! funding.

use namada_core::dec::Dec;
use namada_core::uint::Uint;

/// Holds the PD controller values that should be updated in storage
#[allow(missing_docs)]
pub struct PosValsToUpdate {
    pub locked_ratio: Dec,
    pub inflation: Uint,
}

/// Holds the PD controller values that should be updated in storage
#[allow(missing_docs)]
pub struct ShieldedValsToUpdate {
    pub inflation: Uint,
}

/// PD controller used to dynamically adjust the rewards rates
#[derive(Debug, Clone)]
pub struct PosRewardsController {
    /// Locked token amount in the relevant system
    pub locked_tokens: Uint,
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

impl PosRewardsController {
    /// Calculate a new inflation rate for the Proof-of-stake rewards system.
    /// Uses the ratios of locked (staked) tokens to the total native token
    /// supply to determine the new inflation amount.
    pub fn run(self) -> PosValsToUpdate {
        let Self {
            locked_tokens,
            total_native_tokens,
            locked_ratio_target,
            locked_ratio_last,
            max_reward_rate,
            last_inflation_amount,
            p_gain_nom,
            d_gain_nom,
            epochs_per_year,
        } = self;

        // Token amounts must be expressed in terms of the raw amount
        // to properly run the PD controller
        let locked = Dec::try_from(locked_tokens)
            .expect("Should not fail to convert Uint to Dec");
        let total_native = Dec::try_from(total_native_tokens)
            .expect("Should not fail to convert Uint to Dec");
        let last_inflation_amount = Dec::try_from(last_inflation_amount)
            .expect("Should not fail to convert Uint to Dec");

        let epochs_py: Dec = epochs_per_year.into();

        // Staked ratio
        let locked_ratio = if total_native.is_zero() {
            Dec::one()
        } else {
            locked / total_native
        };

        // Max inflation amount for this epoch
        let max_inflation = total_native * max_reward_rate / epochs_py;

        // Intermediate values
        let p_gain = p_gain_nom * max_inflation;
        let d_gain = d_gain_nom * max_inflation;
        let error = locked_ratio_target - locked_ratio;
        let delta_error = locked_ratio_last - locked_ratio;
        let control_val = p_gain * error - d_gain * delta_error;

        // New inflation amount
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
        PosValsToUpdate {
            locked_ratio,
            inflation,
        }
    }
}

/// PD controller used to dynamically adjust the rewards rates
#[derive(Debug, Clone)]
pub struct ShieldedRewardsController {
    /// Locked token amount in the relevant system
    pub locked_tokens: Uint,
    /// Total native token supply
    pub total_native_tokens: Uint,
    /// PD target locked amount
    pub locked_tokens_target: Uint,
    /// PD last locked amount
    pub locked_tokens_last: Uint,
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

impl ShieldedRewardsController {
    /// Calculate a new inflation rate for the Proof-of-stake rewards system.
    /// Uses the ratios of locked (staked) tokens to the total native token
    /// supply to determine the new inflation amount.
    pub fn run(self) -> ShieldedValsToUpdate {
        let Self {
            locked_tokens,
            total_native_tokens,
            locked_tokens_target,
            locked_tokens_last,
            max_reward_rate,
            last_inflation_amount,
            p_gain_nom,
            d_gain_nom,
            epochs_per_year,
        } = self;

        // Token amounts must be expressed in terms of the raw amount
        // to properly run the PD controller
        let locked = Dec::try_from(locked_tokens)
            .expect("Should not fail to convert Uint to Dec");
        let locked_amount_target = Dec::try_from(locked_tokens_target)
            .expect("Should not fail to convert Uint to Dec");
        let locked_amount_last = Dec::try_from(locked_tokens_last)
            .expect("Should not fail to convert Uint to Dec");
        let total_native = Dec::try_from(total_native_tokens)
            .expect("Should not fail to convert Uint to Dec");
        let last_inflation_amount = Dec::try_from(last_inflation_amount)
            .expect("Should not fail to convert Uint to Dec");

        let epochs_py: Dec = epochs_per_year.into();

        // Max inflation amount for this epoch
        let max_inflation = total_native * max_reward_rate / epochs_py;

        // Intermediate values
        let p_gain = p_gain_nom * max_reward_rate / epochs_py;
        let d_gain = d_gain_nom * max_reward_rate / epochs_py;
        let error = locked_amount_target - locked;
        let delta_error = locked_amount_last - locked;
        let control_val = p_gain * error - d_gain * delta_error;

        // New inflation amount
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
        ShieldedValsToUpdate { inflation }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_inflation_calc_up() {
        let mut controller = PosRewardsController {
            locked_tokens: Uint::from(2_000_000_000),
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

        let PosValsToUpdate {
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
        controller.locked_tokens += inflation_0;

        let PosValsToUpdate {
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
        controller.locked_tokens += inflation_1;

        let PosValsToUpdate {
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
        let mut controller = PosRewardsController {
            locked_tokens: Uint::from(900_000_000),
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

        let PosValsToUpdate {
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
        controller.locked_tokens += inflation_0;

        let PosValsToUpdate {
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
        controller.locked_tokens += inflation_1;

        let PosValsToUpdate {
            locked_ratio: locked_ratio_2,
            inflation: inflation_2,
        } = controller.run();
        println!(
            "Round 2: Locked ratio: {locked_ratio_2}, inflation: {inflation_2}",
        );
        assert_eq!(locked_ratio_2, locked_ratio_1);
        assert_eq!(inflation_2, Uint::zero());
    }

    #[test]
    fn test_inflation_playground() {
        let init_locked_ratio = Dec::from_str("0.1").unwrap();
        let total_tokens = 1_000_000_000_000_000_u64;
        let epochs_per_year = 365_u64;

        let staking_growth = Dec::from_str("0.04").unwrap();
        // let mut do_add = true;

        // let a = (init_locked_ratio * total_tokens).to_uint().unwrap();
        let num_rounds = 100;

        let mut controller = PosRewardsController {
            locked_tokens: (init_locked_ratio * total_tokens)
                .to_uint()
                .unwrap(),
            total_native_tokens: Uint::from(total_tokens),
            locked_ratio_target: Dec::from_str("0.66666666").unwrap(),
            locked_ratio_last: init_locked_ratio,
            max_reward_rate: Dec::from_str("0.1").unwrap(),
            last_inflation_amount: Uint::zero(),
            p_gain_nom: Dec::from_str("0.25").unwrap(),
            d_gain_nom: Dec::from_str("0.25").unwrap(),
            epochs_per_year,
        };
        dbg!(&controller);

        for round in 0..num_rounds {
            let PosValsToUpdate {
                locked_ratio,
                inflation,
            } = controller.clone().run();
            let rate = Dec::try_from(inflation).unwrap()
                * Dec::from(epochs_per_year)
                / Dec::from(total_tokens);
            println!(
                "Round {round}: Locked ratio: {locked_ratio}, inflation rate: \
                 {rate}",
            );
            controller.last_inflation_amount = inflation;
            controller.total_native_tokens += inflation;

            // if rate.abs_diff(&controller.max_reward_rate)
            //     < Dec::from_str("0.01").unwrap()
            // {
            //     controller.locked_tokens = controller.total_tokens;
            // }

            let tot_tokens =
                u64::try_from(controller.total_native_tokens).unwrap();
            let change_staked_tokens =
                (staking_growth * tot_tokens).to_uint().unwrap();
            controller.locked_tokens = std::cmp::min(
                controller.total_native_tokens,
                controller.locked_tokens + change_staked_tokens,
            );

            // if locked_ratio > Dec::from_str("0.8").unwrap()
            //     && locked_ratio - controller.locked_ratio_last >= Dec::zero()
            // {
            //     do_add = false;
            // } else if locked_ratio < Dec::from_str("0.4").unwrap()
            //     && locked_ratio - controller.locked_ratio_last < Dec::zero()
            // {
            //     do_add = true;
            // }

            // controller.locked_tokens = std::cmp::min(
            //     if do_add {
            //         controller.locked_tokens + change_staked_tokens
            //     } else {
            //         controller.locked_tokens - change_staked_tokens
            //     },
            //     controller.total_tokens,
            // );

            controller.locked_ratio_last = locked_ratio;
        }

        // controller.locked_ratio_last = locked_ratio_1;
        // controller.last_inflation_amount = inflation_1;
        // controller.total_tokens += inflation_1;
        // controller.locked_tokens += inflation_1;
    }
}
