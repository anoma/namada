use namada_core::ledger::governance::storage::proposal::{PGFTarget, StoragePgfFunding};
use namada_core::ledger::pgf::storage::steward::StewardDetail;

use crate::core::ledger::pgf::parameters::PgfParameters;
use crate::ledger::queries::types::RequestCtx;
use crate::ledger::storage::{DBIter, StorageHasher, DB};
use crate::ledger::storage_api;

// PoS validity predicate queries
router! {PGF,
    ( "stewards" ) -> Vec<StewardDetail> = stewards,
    ( "fundings" ) -> Vec<PGFTarget> = funding,
    ( "parameters" ) -> PgfParameters = parameters,
}

/// Query the currect pgf steward set
fn stewards<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<Vec<StewardDetail>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::pgf::get_stewards(ctx.wl_storage)
}

/// Query the continous pgf fundings
fn funding<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<Vec<StoragePgfFunding>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::pgf::get_payments(ctx.wl_storage)
}

/// Query the PGF parameters
fn parameters<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<PgfParameters>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::pgf::get_parameters(ctx.wl_storage)
}
