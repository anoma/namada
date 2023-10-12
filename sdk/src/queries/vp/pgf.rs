use namada_core::ledger::governance::storage::proposal::StoragePgfFunding;
use namada_core::ledger::pgf::parameters::PgfParameters;
use namada_core::ledger::pgf::storage::steward::StewardDetail;
use namada_core::ledger::storage::{DBIter, StorageHasher, DB};
use namada_core::ledger::storage_api;
use namada_core::types::address::Address;

use crate::queries::types::RequestCtx;

// PoS validity predicate queries
router! {PGF,
    ( "stewards" / [ address: Address ] ) -> bool = is_steward,
    ( "stewards" ) -> Vec<StewardDetail> = stewards,
    ( "fundings" ) -> Vec<StoragePgfFunding> = funding,
    ( "parameters" ) -> PgfParameters = parameters,
}

/// Query the currect pgf steward set
fn stewards<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> storage_api::Result<Vec<StewardDetail>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::pgf::get_stewards(ctx.wl_storage)
}

/// Check if an address is a pgf steward
fn is_steward<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    address: Address,
) -> storage_api::Result<bool>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::pgf::is_steward(ctx.wl_storage, &address)
}

/// Query the continous pgf fundings
fn funding<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> storage_api::Result<Vec<StoragePgfFunding>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::pgf::get_payments(ctx.wl_storage)
}

/// Query the PGF parameters
fn parameters<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> storage_api::Result<PgfParameters>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::pgf::get_parameters(ctx.wl_storage)
}
