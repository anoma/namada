use namada_core::ledger::storage::{DBIter, StorageHasher, DB};
use namada_core::ledger::storage_api;
use namada_core::ledger::storage_api::token::read_denom;
use namada_core::types::address::Address;
use namada_core::types::token;
use namada_core::types::token::Denomination;

use crate::ledger::queries::RequestCtx;

router! {TOKEN,
    ( "denomination" / [addr: Address] ) -> Option<token::Denomination> = denomination,
}

/// Get the number of decimal places (in base 10) for a
/// token specified by `addr`.
fn denomination<D, H>(
    ctx: RequestCtx<'_, D, H>,
    addr: Address,
) -> storage_api::Result<Option<Denomination>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_denom(ctx.wl_storage, &addr)
}
