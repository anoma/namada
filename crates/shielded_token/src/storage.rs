use namada_core::address::{self, Address};
use namada_core::arith::checked;
use namada_core::token;
use namada_core::token::Amount;
use namada_core::uint::Uint;
use namada_storage as storage;
use namada_storage::{StorageRead, StorageWrite};
use namada_trans_token::credit_tokens;
use storage::ResultExt;

use crate::storage_key::*;
use crate::ShieldedParams;

/// Initialize parameters for the token in storage during the genesis block.
pub fn write_params<S>(
    params: &ShieldedParams,
    storage: &mut S,
    address: &Address,
    denom: &token::Denomination,
) -> storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let ShieldedParams {
        max_reward_rate: max_rate,
        kd_gain_nom,
        kp_gain_nom,
        locked_amount_target,
    } = params;
    storage.write(&masp_last_inflation_key(address), Amount::zero())?;
    storage.write(&masp_last_locked_amount_key(address), Amount::zero())?;
    storage.write(&masp_max_reward_rate_key(address), max_rate)?;
    storage.write(&masp_kp_gain_key(address), kp_gain_nom)?;
    storage.write(&masp_kd_gain_key(address), kd_gain_nom)?;

    let locked_amount_target = Uint::from(*locked_amount_target);
    let raw_target = checked!(
        locked_amount_target * (Uint::from(10) ^ Uint::from(denom.0))
    )?;
    let raw_target = Amount::from_uint(raw_target, 0).into_storage_result()?;
    storage.write(&masp_locked_amount_target_key(address), raw_target)?;
    Ok(())
}

/// Mint MASP rewards tokens and increment the stored total rewards.
pub fn mint_rewards<S>(
    storage: &mut S,
    amount: token::Amount,
) -> storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let native_token = storage.get_native_token()?;
    credit_tokens(storage, &native_token, &address::MASP, amount)?;

    let total_rewards_key = masp_total_rewards();
    let mut total_rewards = read_total_rewards(storage)?;
    checked!(total_rewards += amount)?;
    storage.write(&total_rewards_key, total_rewards)
}

/// Read the total rewards minted by MASP.
pub fn read_total_rewards<S>(storage: &S) -> storage::Result<token::Amount>
where
    S: StorageRead,
{
    let total_rewards_key = masp_total_rewards();
    let total_rewards: token::Amount =
        storage.read(&total_rewards_key)?.unwrap_or_default();
    Ok(total_rewards)
}
