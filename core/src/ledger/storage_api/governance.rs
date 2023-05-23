//! Governance

use std::collections::{BTreeMap, BTreeSet};

use borsh::BorshDeserialize;

use super::token;
use crate::ledger::governance::storage::keys as governance_keys;
use crate::ledger::governance::storage::proposal::{
    ProposalType, StorageProposal,
};
use crate::ledger::governance::storage::vote::StorageVoteWrapper;
use crate::ledger::governance::utils::Vote;
use crate::ledger::governance::ADDRESS as governance_address;
use crate::ledger::storage_api::{self, StorageRead, StorageWrite};
use crate::types::address::Address;
use crate::types::storage::Epoch;
use crate::types::transaction::governance::{
    InitDelegate, InitProposalData, UpdateDelegate, UpdateDelegateAction,
    VoteProposalData,
};

/// A proposal creation transaction.
pub fn init_proposal<S>(
    storage: &mut S,
    data: InitProposalData,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let counter_key = governance_keys::get_counter_key();
    let proposal_id = if let Some(id) = data.id {
        id
    } else {
        storage.read(&counter_key)?.unwrap()
    };

    let content_key = governance_keys::get_content_key(proposal_id);
    storage.write_bytes(&content_key, data.content)?;

    let author_key = governance_keys::get_author_key(proposal_id);
    storage.write(&author_key, data.author.clone())?;

    let proposal_type_key = governance_keys::get_proposal_type_key(proposal_id);
    match data.r#type {
        ProposalType::Default(Some(ref code)) => {
            // Remove wasm code and write it under a different subkey
            storage.write(&proposal_type_key, ProposalType::Default(None))?;
            let proposal_code_key =
                governance_keys::get_proposal_code_key(proposal_id);
            storage.write_bytes(&proposal_code_key, code)?
        }
        _ => storage.write(&proposal_type_key, data.r#type.clone())?,
    }

    let voting_start_epoch_key =
        governance_keys::get_voting_start_epoch_key(proposal_id);
    storage.write(&voting_start_epoch_key, data.voting_start_epoch)?;

    let voting_end_epoch_key =
        governance_keys::get_voting_end_epoch_key(proposal_id);
    storage.write(&voting_end_epoch_key, data.voting_end_epoch)?;

    let grace_epoch_key = governance_keys::get_grace_epoch_key(proposal_id);
    storage.write(&grace_epoch_key, data.grace_epoch)?;

    if let ProposalType::Default(Some(proposal_code)) = data.r#type {
        let proposal_code_key =
            governance_keys::get_proposal_code_key(proposal_id);
        storage.write_bytes(&proposal_code_key, proposal_code)?;
    }

    storage.write(&counter_key, proposal_id + 1)?;

    let min_proposal_funds_key = governance_keys::get_min_proposal_fund_key();
    let min_proposal_funds: token::Amount =
        storage.read(&min_proposal_funds_key)?.unwrap();

    let funds_key = governance_keys::get_funds_key(proposal_id);
    storage.write(&funds_key, min_proposal_funds)?;

    // this key must always be written for each proposal
    let committing_proposals_key =
        governance_keys::get_committing_proposals_key(
            proposal_id,
            data.grace_epoch.0,
        );
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
    let vote = StorageVoteWrapper::from(data.clone());
    let vote_key = governance_keys::get_vote_proposal_key(data.id, data.voter);

    storage.write(&vote_key, vote)
}

/// Read a proposal by id from storage
pub fn get_proposal_by_id<S>(
    storage: &S,
    id: u64,
) -> storage_api::Result<Option<StorageProposal>>
where
    S: StorageRead + StorageWrite,
{
    let author_key = governance_keys::get_author_key(id);
    let content = governance_keys::get_content_key(id);
    let start_epoch_key = governance_keys::get_voting_start_epoch_key(id);
    let end_epoch_key = governance_keys::get_voting_end_epoch_key(id);
    let grace_epoch_key = governance_keys::get_grace_epoch_key(id);
    let proposal_type_key = governance_keys::get_proposal_type_key(id);

    let author: Option<Address> = storage.read(&author_key)?;
    let content: Option<BTreeMap<String, String>> = storage.read(&content)?;
    let voting_start_epoch: Option<Epoch> = storage.read(&start_epoch_key)?;
    let voting_end_epoch: Option<Epoch> = storage.read(&end_epoch_key)?;
    let grace_epoch: Option<Epoch> = storage.read(&grace_epoch_key)?;
    let proposal_type: Option<ProposalType> =
        storage.read(&proposal_type_key)?;

    let proposal = proposal_type.map(|proposal_type| StorageProposal {
        id,
        content: content.unwrap(),
        author: author.unwrap(),
        r#type: proposal_type,
        voting_start_epoch: voting_start_epoch.unwrap(),
        voting_end_epoch: voting_end_epoch.unwrap(),
        grace_epoch: grace_epoch.unwrap(),
    });

    Ok(proposal)
}

/// Query all the votes for a proposal_id
pub fn get_proposal_votes<S>(
    storage: &S,
    proposal_id: u64,
) -> storage_api::Result<Vec<Vote>>
where
    S: storage_api::StorageRead,
{
    let vote_prefix_key =
        governance_keys::get_proposal_vote_prefix_key(proposal_id);
    let vote_iter = storage_api::iter_prefix::<StorageVoteWrapper>(
        storage,
        &vote_prefix_key,
    )?;

    let votes = vote_iter
        .filter_map(|vote_result| {
            if let Ok((vote_key, vote)) = vote_result {
                let voter_address = governance_keys::get_voter_address(&vote_key);
                match voter_address {
                    Some(voter_address) => {
                        Some(Vote {
                            voter: voter_address.clone(),
                            delegate: vote.delegator,
                            data: vote.vote,
                            voting_power: vote.voting_power
                        })
                    }
                    _ => None,
                }
            } else {
                None
            }
        })
        .collect::<Vec<Vote>>();

    Ok(votes)
}

/// Init a new delegatee account
pub fn init_delegate<S>(
    storage: &mut S,
    data: InitDelegate,
) -> storage_api::Result<()>
where
    S: storage_api::StorageRead + storage_api::StorageWrite,
{
    let delegatee_key = governance_keys::get_delegate_key(&data.address);
    storage.write(&delegatee_key, ())
}

/// Update a delegate for a governance delegator
pub fn update_delegate_for<S>(
    storage: &mut S,
    data: UpdateDelegate,
) -> storage_api::Result<()>
where
    S: storage_api::StorageRead + storage_api::StorageWrite,
{
    let delegation_key =
        governance_keys::get_delegation_key(&data.delegate, &data.delegator);
    let inverse_deleagation_key =
        governance_keys::get_inverse_delegation(&data.delegator);

    match data.action {
        UpdateDelegateAction::Add => {
            storage.write(&delegation_key, ())?;
            storage.write(&inverse_deleagation_key, data.delegate)
        }
        UpdateDelegateAction::Remove => {
            storage.delete(&delegation_key)?;
            storage.delete(&inverse_deleagation_key)
        }
    }
}

/// Fetch the current delegate set
pub fn get_delegate_set<S>(
    storage: &S,
) -> storage_api::Result<BTreeSet<Address>>
where
    S: storage_api::StorageRead,
{
    let delegate_prefix_key = governance_keys::get_delegate_prefix_key();
    let delegate_iter =
        storage_api::iter_prefix::<()>(storage, &delegate_prefix_key)?;

    let delegate_set = delegate_iter
        .filter_map(|delegate_result| {
            if let Ok((delegate_key, _)) = delegate_result {
                governance_keys::get_delegate_address(&delegate_key).cloned()
            } else {
                None
            }
        })
        .collect::<BTreeSet<Address>>();

    Ok(delegate_set)
}

/// Check if an address is a delegate
pub fn is_delegate<S>(
    storage: &S,
    address: Address,
) -> storage_api::Result<bool>
where
    S: storage_api::StorageRead,
{
    let delegatee_key = governance_keys::get_delegate_key(&address);
    storage.has_key(&delegatee_key)
}

/// Get all the delegation for a specific delegate
pub fn delegations<S>(
    storage: &S,
    delegate: Address,
) -> storage_api::Result<BTreeSet<Address>>
where
    S: storage_api::StorageRead,
{
    let delegations_prefix_key =
        governance_keys::get_delegations_by_delegate_prefix_key(&delegate);
    let delegations_iter =
        storage_api::iter_prefix::<()>(storage, &delegations_prefix_key)?;

    let delegations = delegations_iter
        .filter_map(|delegate_result| {
            if let Ok((delegation_key, _)) = delegate_result {
                governance_keys::get_delegator_address_from_delegation(
                    &delegation_key,
                )
                .cloned()
            } else {
                None
            }
        })
        .collect::<BTreeSet<Address>>();

    Ok(delegations)
}

/// Get the delegate for a specific delagator
pub fn delegate_for<S>(
    storage: &S,
    delegator: Address,
) -> storage_api::Result<Option<Address>>
where
    S: storage_api::StorageRead,
{
    let inverse_delegation_key =
        governance_keys::get_inverse_delegation(&delegator);
    storage.read(&inverse_delegation_key)
}

/// Check if an accepted proposal is being executed
pub fn is_proposal_accepted<S>(
    storage: &S,
    tx_data: &[u8],
) -> storage_api::Result<bool>
where
    S: storage_api::StorageRead,
{
    let proposal_id = u64::try_from_slice(tx_data).ok();
    match proposal_id {
        Some(id) => {
            let proposal_execution_key =
                governance_keys::get_proposal_execution_key(id);
            storage.has_key(&proposal_execution_key)
        }
        None => Ok(false),
    }
}
