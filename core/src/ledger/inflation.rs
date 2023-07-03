//! General inflation system that will be used to process rewards for
//! proof-of-stake, providing liquity to shielded asset pools, and public goods
//! funding.

use namada_core::types::dec::Dec;

use crate::ledger::storage_api::{self, StorageRead, StorageWrite};
use crate::types::address::Address;
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
        locked_ratio_target: Decimal,
        locked_ratio_last: Decimal,
        max_reward_rate: Decimal,
        last_inflation_amount: token::Amount,
        p_gain_nom: Decimal,
        d_gain_nom: Decimal,
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
        let locked =
            Dec::try_from(locked_tokens.raw_amount()).expect("Should not fail");
        let total =
            Dec::try_from(total_tokens.raw_amount()).expect("Should not fail");
        let epochs_py: Dec = epochs_per_year.into();

        let locked_ratio = locked / total;
        let max_inflation = total * max_reward_rate / epochs_py;
        let p_gain = p_gain_nom * max_inflation;
        let d_gain = d_gain_nom * max_inflation;

        let error = locked_ratio_target - locked_ratio;
        let delta_error = locked_ratio_last - locked_ratio;
        let control_val = p_gain * error - d_gain * delta_error;

        let last_inflation_amount = Dec::from(last_inflation_amount);
        let new_inflation_amount = last_inflation_amount + control_val;
        let inflation = if last_inflation_amount + control_val > max_inflation {
            max_inflation
        } else if new_inflation_amount > Dec::zero() {
            new_inflation_amount
        } else {
            Dec::zero()
        };
        let inflation = token::Amount::from(inflation);

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
        .read(&token::total_supply_key(token))?
        .unwrap_or_default();
    total_tokens.receive(&amount);
    storage.write(&token::total_supply_key(token), total_tokens)?;

    Ok(())
}
