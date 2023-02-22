//! Governance

use super::token;
use crate::ledger::governance::{storage, ADDRESS as governance_address};
use crate::ledger::storage_api::{self, StorageRead, StorageWrite};
use crate::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};

/// A proposal creation transaction.
pub fn init_proposal<S>(
    storage: &mut S,
    data: InitProposalData,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let counter_key = storage::get_counter_key();
    let proposal_id = if let Some(id) = data.id {
        id
    } else {
        storage.read(&counter_key)?.unwrap()
    };

    let content_key = storage::get_content_key(proposal_id);
    storage.write_bytes(&content_key, data.content)?;

    let author_key = storage::get_author_key(proposal_id);
    storage.write(&author_key, data.author.clone())?;

    let voting_start_epoch_key =
        storage::get_voting_start_epoch_key(proposal_id);
    storage.write(&voting_start_epoch_key, data.voting_start_epoch)?;

    let voting_end_epoch_key = storage::get_voting_end_epoch_key(proposal_id);
    storage.write(&voting_end_epoch_key, data.voting_end_epoch)?;

    let grace_epoch_key = storage::get_grace_epoch_key(proposal_id);
    storage.write(&grace_epoch_key, data.grace_epoch)?;

    if let Some(proposal_code) = data.proposal_code {
        let proposal_code_key = storage::get_proposal_code_key(proposal_id);
        storage.write_bytes(&proposal_code_key, proposal_code)?;
    }

    storage.write(&counter_key, proposal_id + 1)?;

    let min_proposal_funds_key = storage::get_min_proposal_fund_key();
    let min_proposal_funds: token::Amount =
        storage.read(&min_proposal_funds_key)?.unwrap();

    let funds_key = storage::get_funds_key(proposal_id);
    storage.write(&funds_key, min_proposal_funds)?;

    println!("{:?}", &funds_key);

    // this key must always be written for each proposal
    let committing_proposals_key =
        storage::get_committing_proposals_key(proposal_id, data.grace_epoch.0);
    storage.write(&committing_proposals_key, ())?;

    token::transfer(
        storage,
        &storage.get_native_token()?,
        &data.author,
        &governance_address,
        min_proposal_funds,
    )
}

/// A proposal vote transaction.
pub fn vote_proposal<S>(
    storage: &mut S,
    data: VoteProposalData,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    for delegation in data.delegations {
        let vote_key = storage::get_vote_proposal_key(
            data.id,
            data.voter.clone(),
            delegation,
        );
        storage.write(&vote_key, data.vote.clone())?;

    }
    Ok(())
}
