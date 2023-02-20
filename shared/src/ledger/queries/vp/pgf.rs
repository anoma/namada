use namada_core::ledger::storage_api::pgf::{get_current_counsil, get_candidates, get_receipients};
use namada_core::types::transaction::pgf::PgfProjectsUpdate;

use crate::ledger::queries::types::RequestCtx;
use crate::ledger::storage::{DBIter, StorageHasher, DB};
use crate::ledger::storage_api;
use crate::types::address::Address;
use crate::types::storage::Epoch;
use crate::types::token;

type Counsil = (Address, token::Amount, token::Amount);
type Candidate = (Address, token::Amount, String);

router! {PGF,
    ( "current_counsil" ) -> Option<Counsil> = current_counsil,
    ( "candidates"  ) -> Vec<Candidate> = candidates,
    ( "receipients"  ) -> Option<PgfProjectsUpdate> = receipients,
}

/// Get the current counsil info
fn current_counsil<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<Option<Counsil>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    get_current_counsil(ctx.wl_storage)
}

/// Get the current counsil info
fn candidates<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<Vec<Candidate>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    get_candidates(ctx.wl_storage)
}

/// Get the current counsil receipients
fn receipients
<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<Option<PgfProjectsUpdate>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    get_receipients(ctx.wl_storage)
}