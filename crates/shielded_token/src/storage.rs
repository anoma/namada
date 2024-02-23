use namada_core::address::Address;
use namada_core::token;
use namada_core::token::Amount;
use namada_core::uint::Uint;
use namada_storage as storage;
use namada_storage::{StorageRead, StorageWrite};
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

    let raw_target = Uint::from(*locked_amount_target)
        * Uint::from(10).checked_pow(Uint::from(denom.0)).unwrap();
    let raw_target = Amount::from_uint(raw_target, 0).into_storage_result()?;
    storage.write(&masp_locked_amount_target_key(address), raw_target)?;
    Ok(())
}
