// cd shared && cargo expand ledger::queries::vp::governance

use namada_governance::parameters::GovernanceParameters;
use namada_governance::storage::proposal::StorageProposal;
use namada_governance::utils::Vote;
use namada_state::{DBIter, StorageHasher, DB};

use crate::queries::types::RequestCtx;

// Governance queries
router! {GOV,
    ( "proposal" / [id: u64 ] ) -> Option<StorageProposal> = proposal_id,
    ( "proposal" / [id: u64 ] / "votes" ) -> Vec<Vote> = proposal_id_votes,
    ( "parameters" ) -> GovernanceParameters = parameters,
}

/// Find if the given address belongs to a validator account.
fn proposal_id<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    id: u64,
) -> namada_storage::Result<Option<StorageProposal>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_governance::storage::get_proposal_by_id(ctx.wl_storage, id)
}

/// Find if the given address belongs to a validator account.
fn proposal_id_votes<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    id: u64,
) -> namada_storage::Result<Vec<Vote>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_governance::storage::get_proposal_votes(ctx.wl_storage, id)
}

/// Get the governane parameters
fn parameters<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<GovernanceParameters>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_governance::storage::get_parameters(ctx.wl_storage)
}
