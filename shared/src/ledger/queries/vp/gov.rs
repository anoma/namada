use namada_core::ledger::storage_api;

use crate::ledger::queries::types::RequestCtx;
use crate::ledger::storage::{DBIter, StorageHasher, DB};
use crate::types::governance::Proposal;

// Governance validity predicate queries
router! {GOV,
    // ( "proposals" ) -> Vec<Proposal> = proposals,

    ( "proposal" / [id: u64 ] ) -> Option<Proposal> = proposal_by_id,
    // ( "parameters" ) -> GovParams = parameters
}

// /// Find all proposals
// fn proposals<D, H>(
//     ctx: RequestCtx<'_, D, H>,
// ) -> storage_api::Result<Vec<Proposal>>
// where
//     D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
//     H: 'static + StorageHasher + Sync,
// {
//     let author_key = gov_storage::get_author_key(id);
//     let start_epoch_key = gov_storage::get_voting_start_epoch_key(id);
//     let end_epoch_key = gov_storage::get_voting_end_epoch_key(id);
//     let proposal_type_key = gov_storage::get_proposal_type_key(id);
//     let content_key = gov_storage::get_content_key(id);
//     let grace_epoch_key = gov_storage::get_grace_epoch_key(id);

//     let author = ctx.wl_storage
// }

/// Find proposal by proposal id
fn proposal_by_id<D, H>(
    ctx: RequestCtx<'_, D, H>,
    id: u64,
) -> storage_api::Result<Option<Proposal>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    Ok(None)
}
