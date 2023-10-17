//! Pgf

use std::collections::HashMap;

use crate::ledger::governance::storage::proposal::StoragePgfFunding;
use crate::ledger::pgf::parameters::PgfParameters;
use crate::ledger::pgf::storage::keys as pgf_keys;
use crate::ledger::pgf::storage::steward::StewardDetail;
use crate::ledger::storage_api::{self};
use crate::types::address::Address;
use crate::types::dec::Dec;

/// Query the current pgf steward set
pub fn get_stewards<S>(storage: &S) -> storage_api::Result<Vec<StewardDetail>>
where
    S: storage_api::StorageRead,
{
    let stewards = pgf_keys::stewards_handle()
        .iter(storage)?
        .filter_map(|data| match data {
            Ok((_, steward)) => Some(steward),
            Err(_) => None,
        })
        .collect::<Vec<StewardDetail>>();

    Ok(stewards)
}

/// Query the a steward by address
pub fn get_steward<S>(
    storage: &S,
    address: &Address,
) -> storage_api::Result<Option<StewardDetail>>
where
    S: storage_api::StorageRead,
{
    pgf_keys::stewards_handle().get(storage, address)
}

/// Check if an address is a steward
pub fn is_steward<S>(
    storage: &S,
    address: &Address,
) -> storage_api::Result<bool>
where
    S: storage_api::StorageRead,
{
    pgf_keys::stewards_handle().contains(storage, address)
}

/// Remove a steward
pub fn remove_steward<S>(
    storage: &mut S,
    address: &Address,
) -> storage_api::Result<()>
where
    S: storage_api::StorageRead + storage_api::StorageWrite,
{
    pgf_keys::stewards_handle().remove(storage, address)?;

    Ok(())
}

/// Query the current pgf continous payments
pub fn get_payments<S>(
    storage: &S,
) -> storage_api::Result<Vec<StoragePgfFunding>>
where
    S: storage_api::StorageRead,
{
    let fundings = pgf_keys::fundings_handle()
        .iter(storage)?
        .filter_map(|data| match data {
            Ok((_, funding)) => Some(funding),
            Err(_) => None,
        })
        .collect::<Vec<StoragePgfFunding>>();

    Ok(fundings)
}

/// Query the pgf parameters
pub fn get_parameters<S>(storage: &S) -> storage_api::Result<PgfParameters>
where
    S: storage_api::StorageRead,
{
    let pgf_inflation_rate_key = pgf_keys::get_pgf_inflation_rate_key();
    let stewards_inflation_rate_key =
        pgf_keys::get_steward_inflation_rate_key();

    let pgf_inflation_rate: Dec = storage
        .read(&pgf_inflation_rate_key)?
        .expect("Parameter should be defined.");
    let stewards_inflation_rate: Dec = storage
        .read(&stewards_inflation_rate_key)?
        .expect("Parameter should be defined.");

    Ok(PgfParameters {
        pgf_inflation_rate,
        stewards_inflation_rate,
        ..Default::default()
    })
}

/// Update the commission for a steward
pub fn update_commission<S>(
    storage: &mut S,
    address: Address,
    reward_distribution: HashMap<Address, Dec>,
) -> storage_api::Result<()>
where
    S: storage_api::StorageRead + storage_api::StorageWrite,
{
    pgf_keys::stewards_handle().insert(
        storage,
        address.clone(),
        StewardDetail {
            address,
            reward_distribution,
        },
    )?;

    Ok(())
}
