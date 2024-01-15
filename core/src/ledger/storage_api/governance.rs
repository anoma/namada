//! Governance

use std::collections::BTreeMap;

use borsh::BorshDeserialize;

use super::token;
use crate::ledger::governance::parameters::GovernanceParameters;
use crate::ledger::governance::storage::keys as governance_keys;
use crate::ledger::governance::storage::proposal::{
    ProposalType, StorageProposal,
};
use crate::ledger::governance::storage::vote::ProposalVote;
use crate::ledger::governance::utils::Vote;
use crate::ledger::governance::ADDRESS as governance_address;
use crate::ledger::storage_api::{self, StorageRead, StorageWrite};
use crate::types::address::Address;
use crate::types::storage::Epoch;
use crate::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};

/// A proposal creation transaction.
pub fn init_proposal<S>(
    storage: &mut S,
    data: InitProposalData,
    content: Vec<u8>,
    code: Option<Vec<u8>>,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let counter_key = governance_keys::get_counter_key();
    let proposal_id = storage.read(&counter_key)?.expect(
        "Storage should have been initialized with an initial governance \
         proposal id",
    );

    let content_key = governance_keys::get_content_key(proposal_id);
    storage.write_bytes(&content_key, content)?;

    let author_key = governance_keys::get_author_key(proposal_id);
    storage.write(&author_key, data.author.clone())?;

    let proposal_type_key = governance_keys::get_proposal_type_key(proposal_id);
    match data.r#type {
        ProposalType::Default(Some(_)) => {
            // Remove wasm code and write it under a different subkey
            storage.write(&proposal_type_key, ProposalType::Default(None))?;
            let proposal_code_key =
                governance_keys::get_proposal_code_key(proposal_id);
            let proposal_code = code.clone().ok_or(
                storage_api::Error::new_const("Missing proposal code"),
            )?;
            storage.write_bytes(&proposal_code_key, proposal_code)?
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

    if let ProposalType::Default(Some(_)) = data.r#type {
        let proposal_code_key =
            governance_keys::get_proposal_code_key(proposal_id);
        let proposal_code =
            code.ok_or(storage_api::Error::new_const("Missing proposal code"))?;
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
    for delegation in data.delegations {
        let vote_key = governance_keys::get_vote_proposal_key(
            data.id,
            data.voter.clone(),
            delegation,
        );
        storage.write(&vote_key, data.vote.clone())?;
    }
    Ok(())
}

/// Read a proposal by id from storage
pub fn get_proposal_by_id<S>(
    storage: &S,
    id: u64,
) -> storage_api::Result<Option<StorageProposal>>
where
    S: StorageRead,
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
    let vote_iter =
        storage_api::iter_prefix::<ProposalVote>(storage, &vote_prefix_key)?;

    let votes = vote_iter
        .filter_map(|vote_result| {
            if let Ok((vote_key, vote)) = vote_result {
                let voter_address =
                    governance_keys::get_voter_address(&vote_key);
                let delegator_address =
                    governance_keys::get_vote_delegation_address(&vote_key);
                match (voter_address, delegator_address) {
                    (Some(delegator_address), Some(validator_address)) => {
                        Some(Vote {
                            validator: validator_address.to_owned(),
                            delegator: delegator_address.to_owned(),
                            data: vote,
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

/// Get governance parameters
pub fn get_parameters<S>(
    storage: &S,
) -> storage_api::Result<GovernanceParameters>
where
    S: storage_api::StorageRead,
{
    let key = governance_keys::get_max_proposal_code_size_key();
    let max_proposal_code_size: u64 =
        storage.read(&key)?.expect("Parameter should be defined.");

    let key = governance_keys::get_max_proposal_content_key();
    let max_proposal_content_size: u64 =
        storage.read(&key)?.expect("Parameter should be defined.");

    let key = governance_keys::get_min_proposal_fund_key();
    let min_proposal_fund: token::Amount =
        storage.read(&key)?.expect("Parameter should be defined.");

    let key = governance_keys::get_min_proposal_grace_epoch_key();
    let min_proposal_grace_epochs: u64 =
        storage.read(&key)?.expect("Parameter should be defined.");

    let key = governance_keys::get_min_proposal_voting_period_key();
    let min_proposal_voting_period: u64 =
        storage.read(&key)?.expect("Parameter should be defined.");

    let max_proposal_period: u64 = get_max_proposal_period(storage)?;

    Ok(GovernanceParameters {
        min_proposal_fund,
        max_proposal_code_size,
        min_proposal_voting_period,
        max_proposal_period,
        max_proposal_content_size,
        min_proposal_grace_epochs,
    })
}

/// Get governance "max_proposal_period" parameter
pub fn get_max_proposal_period<S>(storage: &S) -> storage_api::Result<u64>
where
    S: storage_api::StorageRead,
{
    let key = governance_keys::get_max_proposal_period_key();
    let max_proposal_period: u64 =
        storage.read(&key)?.expect("Parameter should be defined.");
    Ok(max_proposal_period)
}
