use namada_proof_of_stake::PosReadOnly;

use crate::ledger::pos::BondId;
use crate::ledger::queries::types::{RequestCtx, RequestQuery, ResponseQuery};
use crate::ledger::queries::{require_latest_height, require_no_proof};
use crate::ledger::storage::{DBIter, StorageHasher, DB};
use crate::ledger::storage_api;
use crate::types::address::Address;
use crate::types::storage::Epoch;
use crate::types::token;

// PoS validity predicate queries
router! {POS,
    ( "is_validator" / [addr: Address] ) -> bool = is_validator,

    ( "bond_amount" / [owner: Address] / [validator: Address] / [epoch: opt Epoch] )
    -> token::Amount = bond_amount,
}

// Handlers that implement the functions via `trait StorageRead`:

/// Find if the given address belongs to a validator account.
fn is_validator<D, H>(
    ctx: RequestCtx<'_, D, H>,
    request: &RequestQuery,
    addr: Address,
) -> storage_api::Result<ResponseQuery<bool>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    require_latest_height(&ctx, request)?;
    require_no_proof(request)?;

    let is_validator = ctx.storage.is_validator(&addr)?;
    Ok(ResponseQuery {
        data: is_validator,
        ..ResponseQuery::default()
    })
}

/// Get the total bond amount for the given bond ID at the given epoch, or the
/// current epoch, if None.
fn bond_amount<D, H>(
    ctx: RequestCtx<'_, D, H>,
    request: &RequestQuery,
    owner: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<ResponseQuery<token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    require_latest_height(&ctx, request)?;
    require_no_proof(request)?;

    let epoch = epoch.unwrap_or(ctx.storage.last_epoch);

    let bond_id = BondId {
        source: owner,
        validator,
    };
    let bond_amount = ctx.storage.get_bond_amount(&bond_id, epoch)?;

    Ok(ResponseQuery {
        data: bond_amount,
        ..ResponseQuery::default()
    })
}
