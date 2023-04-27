use std::collections::BTreeSet;

use namada_core::ledger::governance::storage::proposal::PGFTarget;
use namada_core::types::address::Address;

use crate::ledger::queries::types::RequestCtx;
use crate::ledger::storage::{DBIter, StorageHasher, DB};
use crate::ledger::storage_api;

// PoS validity predicate queries
router! {PGF,
    ( "stewards" ) -> BTreeSet<Address> = stewards,
    ( "fundings" ) -> BTreeSet<PGFTarget> = funding,
}

/// Query the currect pgf steward set
fn stewards<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<BTreeSet<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::pgf::get_stewards(ctx.wl_storage)
}

/// Query the continous pgf fundings
fn funding<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<BTreeSet<PGFTarget>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::pgf::get_payments(ctx.wl_storage)
}
