//! General inflation system that will be used to process rewards for
//! proof-of-stake, providing liquity to shielded asset pools, and public goods
//! funding.

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

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
    pub locked_ratio: Decimal,
    pub p_gain: Decimal,
    pub d_gain: Decimal,
    pub inflation: u64,
}

/// PD controller used to dynamically adjust the rewards rates
#[derive(Debug, Clone)]
pub struct RewardsController {
    locked_tokens: token::Amount,
    total_tokens: token::Amount,
    locked_ratio_target: Decimal,
    locked_ratio_last: Decimal,
    max_reward_rate: Decimal,
    p_gain: Decimal,
    d_gain: Decimal,
    last_inflation_amount: token::Amount,
    epochs_per_year: u64,
}

impl RewardsController {
    /// Initialize a new PD controller
    pub fn new(
        locked_tokens: token::Amount,
        total_tokens: token::Amount,
        locked_ratio_target: Decimal,
        locked_ratio_last: Decimal,
        max_reward_rate: Decimal,
        p_gain: Decimal,
        d_gain: Decimal,
        last_inflation_amount: token::Amount,
        epochs_per_year: u64,
    ) -> Self {
        Self {
            locked_tokens,
            total_tokens,
            locked_ratio_target,
            locked_ratio_last,
            max_reward_rate,
            p_gain,
            d_gain,
            last_inflation_amount,
            epochs_per_year,
        }
    }

    /// Calculate a new rewards rate
    pub fn run(
        Self {
            locked_tokens,
            total_tokens,
            locked_ratio_target,
            locked_ratio_last,
            max_reward_rate,
            p_gain,
            d_gain,
            last_inflation_amount,
            epochs_per_year,
        }: &Self,
    ) -> ValsToUpdate {
        let locked: Decimal = u64::from(*locked_tokens).into();
        let total: Decimal = u64::from(*total_tokens).into();
        let epochs_py: Decimal = (*epochs_per_year).into();

        let locked_ratio = locked / total;
        let error_p = locked_ratio_target - locked_ratio;
        let error_d = locked_ratio_last - locked_ratio;

        let gain_factor = max_reward_rate * total / epochs_py;
        let p_gain_new = p_gain * gain_factor;
        let d_gain_new = d_gain * gain_factor;

        let control_val = p_gain_new * error_p - d_gain_new * error_d;
        let reward_rate = if last_reward_rate + control_val > *max_reward_rate {
            *max_reward_rate
        } else {
            if last_inflation_amount + control_val > dec!(0.0) {
                last_inflation_amount + control_val
            } else {
                dec!(0.0)
            }
        };
        let inflation: u64 = inflation.to_u64().unwrap();

        ValsToUpdate {
            locked_ratio,
            p_gain: p_gain_new,
            d_gain: d_gain_new,
            inflation,
        }
    }
}

/// Function that allows the protocol to mint some number of tokens of a desired
/// type to a destination address.
/// TODO: think of error cases that must be handled.
pub fn mint_tokens<S>(
    storage: &mut S,
    target: &Address,
    token: &Address,
    amount: token::Amount,
) -> storage_api::Result<()>
where
    S: StorageWrite + for<'iter> StorageRead<'iter>,
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
