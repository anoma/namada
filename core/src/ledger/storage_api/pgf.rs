//! Pgf

use std::collections::BTreeSet;

use crate::ledger::governance::storage::proposal::PGFTarget;
use crate::ledger::pgf::parameters::PgfParameters;
use crate::ledger::pgf::storage::keys as pgf_keys;
use crate::ledger::storage_api::{self};
use crate::types::address::Address;
use crate::types::dec::Dec;

/// Query the current pgf steward set
pub fn get_stewards<S>(storage: &S) -> storage_api::Result<BTreeSet<Address>>
where
    S: storage_api::StorageRead,
{
    let stewards_key = pgf_keys::get_stewards_key();
    let stewards: Option<BTreeSet<Address>> = storage.read(&stewards_key)?;

    Ok(stewards.unwrap_or_default())
}

/// Query the current pgf continous payments
pub fn get_payments<S>(storage: &S) -> storage_api::Result<BTreeSet<PGFTarget>>
where
    S: storage_api::StorageRead,
{
    let payment_key = pgf_keys::get_payments_key();
    let payments: Option<BTreeSet<PGFTarget>> = storage.read(&payment_key)?;

    Ok(payments.unwrap_or_default())
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
        .expect("Parameter should be definied.");
    let stewards_inflation_rate: Dec = storage
        .read(&stewards_inflation_rate_key)?
        .expect("Parameter should be definied.");

    Ok(PgfParameters {
        pgf_inflation_rate,
        stewards_inflation_rate,
        ..Default::default()
    })
}
