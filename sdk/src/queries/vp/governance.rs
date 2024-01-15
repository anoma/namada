// cd shared && cargo expand ledger::queries::vp::governance

use namada_core::ledger::governance::parameters::GovernanceParameters;
use namada_core::ledger::governance::storage::proposal::StorageProposal;
use namada_core::ledger::governance::utils::Vote;
use namada_core::ledger::storage::{DBIter, StorageHasher, DB};
use namada_core::ledger::storage_api;

use crate::queries::types::RequestCtx;

// Governance queries
router! {GOV,
    ( "proposal" / [id: u64 ] ) -> Option<StorageProposal> = proposal_id,
    ( "proposal" / [id: u64 ] / "votes" ) -> Vec<Vote> = proposal_id_votes,
    ( "parameters" ) -> GovernanceParameters = parameters,
}

/// Query the provided proposal id
fn proposal_id<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    id: u64,
) -> storage_api::Result<Option<StorageProposal>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::governance::get_proposal_by_id(ctx.wl_storage, id)
}

/// Query all the votes for the given proposal id
fn proposal_id_votes<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    id: u64,
) -> storage_api::Result<Vec<Vote>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::governance::get_proposal_votes(ctx.wl_storage, id)
}

/// Get the governance parameters
fn parameters<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> storage_api::Result<GovernanceParameters>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::governance::get_parameters(ctx.wl_storage)
}
