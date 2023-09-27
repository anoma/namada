//! General inflation system that will be used to process rewards for
//! proof-of-stake, providing liquity to shielded asset pools, and public goods
//! funding.

use crate::ledger::storage_api::{self, StorageRead, StorageWrite};
use crate::types::address::Address;
use crate::types::dec::Dec;
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
    /// Initialize a new PD controller
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        locked_tokens: token::Amount,
        total_tokens: token::Amount,
        locked_ratio_target: Dec,
        locked_ratio_last: Dec,
        max_reward_rate: Dec,
        last_inflation_amount: token::Amount,
        p_gain_nom: Dec,
        d_gain_nom: Dec,
        epochs_per_year: u64,
    ) -> Self {
        Self {
            locked_tokens,
            total_tokens,
            locked_ratio_target,
            locked_ratio_last,
            max_reward_rate,
            last_inflation_amount,
            p_gain_nom,
            d_gain_nom,
            epochs_per_year,
        }
    }

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

        let last_inflation_amount =
            Dec::try_from(last_inflation_amount.raw_amount())
                .expect("Should not fail to convert token Amount to Dec");
        let new_inflation_amount_raw = last_inflation_amount + control_val;
        let new_inflation_amount = if new_inflation_amount_raw.is_negative() {
            token::Amount::zero()
        } else {
            token::Amount::from_uint(
                new_inflation_amount_raw
                    .to_uint()
                    .expect("Should not fail to convert Dec to Uint"),
                0,
            )
            .expect("Should not fail to convert Uint to Amount")
        };

        let max_inflation = token::Amount::from_uint(
            max_inflation
                .to_uint()
                .expect("Should not fail to convert Dec to Uint"),
            0,
        )
        .expect("Should not fail to convert Uint to Amount");

        let inflation = std::cmp::min(new_inflation_amount, max_inflation);
        ValsToUpdate {
            locked_ratio,
            inflation,
        }
    }
}

/// Function that allows the protocol to mint some number of tokens of a desired
/// type to a destination address TODO: think of error cases that must be
/// handled.
pub fn mint_tokens<S>(
    storage: &mut S,
    target: &Address,
    token: &Address,
    amount: token::Amount,
) -> storage_api::Result<()>
where
    S: StorageWrite + StorageRead,
{
    let dest_key = token::balance_key(token, target);
    let mut dest_bal: token::Amount =
        storage.read(&dest_key)?.unwrap_or_default();
    dest_bal.receive(&amount);
    storage.write(&dest_key, dest_bal)?;

    // Update the total supply of the tokens in storage
    let mut total_tokens: token::Amount = storage
        .read(&token::minted_balance_key(token))?
        .unwrap_or_default();
    total_tokens.receive(&amount);
    storage.write(&token::minted_balance_key(token), total_tokens)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use crate::types::token::NATIVE_MAX_DECIMAL_PLACES;

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
