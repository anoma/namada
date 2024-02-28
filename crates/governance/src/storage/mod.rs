//! Governance storage

/// Governance proposal keys
pub mod keys;
/// Proposal structures
pub mod proposal;
/// Vote structures
pub mod vote;

use std::collections::BTreeMap;

use namada_core::address::Address;
use namada_core::borsh::BorshDeserialize;
use namada_core::storage::Epoch;
use namada_storage::{iter_prefix, Error, Result, StorageRead, StorageWrite};
use namada_trans_token as token;

use crate::parameters::GovernanceParameters;
use crate::storage::keys as governance_keys;
use crate::storage::proposal::{
    InitProposalData, ProposalType, StorageProposal, VoteProposalData,
};
use crate::storage::vote::ProposalVote;
use crate::utils::{ProposalResult, Vote};
use crate::ADDRESS as governance_address;

/// A proposal creation transaction.
pub fn init_proposal<S>(
    storage: &mut S,
    data: InitProposalData,
    content: Vec<u8>,
    code: Option<Vec<u8>>,
) -> Result<()>
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
            let proposal_code = code
                .clone()
                .ok_or(Error::new_const("Missing proposal code"))?;
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
            code.ok_or(Error::new_const("Missing proposal code"))?;
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
pub fn vote_proposal<S>(storage: &mut S, data: VoteProposalData) -> Result<()>
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

/// Write the proposal result to storage.
pub fn write_proposal_result<S>(
    storage: &mut S,
    proposal_id: u64,
    proposal_result: ProposalResult,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    let proposal_result_key =
        governance_keys::get_proposal_result_key(proposal_id);
    storage.write(&proposal_result_key, proposal_result)
}

/// Read a proposal by id from storage
pub fn get_proposal_by_id<S>(
    storage: &S,
    id: u64,
) -> Result<Option<StorageProposal>>
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
pub fn get_proposal_votes<S>(storage: &S, proposal_id: u64) -> Result<Vec<Vote>>
where
    S: StorageRead,
{
    let vote_prefix_key =
        governance_keys::get_proposal_vote_prefix_key(proposal_id);
    let vote_iter = iter_prefix::<ProposalVote>(storage, &vote_prefix_key)?;

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
pub fn is_proposal_accepted<S>(storage: &S, tx_data: &[u8]) -> Result<bool>
where
    S: StorageRead,
{
    let proposal_id = u64::try_from_slice(tx_data);
    if let Ok(id) = proposal_id {
        let proposal_execution_key =
            governance_keys::get_proposal_execution_key(id);
        storage.has_key(&proposal_execution_key)
    } else {
        Ok(false)
    }
}

/// Get the code associated with a proposal
pub fn get_proposal_code<S>(
    storage: &S,
    proposal_id: u64,
) -> Result<Option<Vec<u8>>>
where
    S: StorageRead,
{
    let proposal_code_key = governance_keys::get_proposal_code_key(proposal_id);
    storage.read_bytes(&proposal_code_key)
}

/// Get the code associated with a proposal
pub fn get_proposal_author<S>(
    storage: &S,
    proposal_id: u64,
) -> Result<Option<Address>>
where
    S: StorageRead,
{
    let proposal_author_key = governance_keys::get_author_key(proposal_id);
    storage.read::<Address>(&proposal_author_key)
}

/// Get governance parameters
pub fn get_parameters<S>(storage: &S) -> Result<GovernanceParameters>
where
    S: StorageRead,
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
pub fn get_max_proposal_period<S>(storage: &S) -> Result<u64>
where
    S: StorageRead,
{
    let key = governance_keys::get_max_proposal_period_key();
    let max_proposal_period: u64 =
        storage.read(&key)?.expect("Parameter should be defined.");
    Ok(max_proposal_period)
}

/// Get governance proposal result stored in storage if proposal ended
pub fn get_proposal_result<S>(
    storage: &S,
    proposal_id: u64,
) -> Result<Option<ProposalResult>>
where
    S: StorageRead,
{
    let key = governance_keys::get_proposal_result_key(proposal_id);
    let proposal_result: Option<ProposalResult> = storage.read(&key)?;
    Ok(proposal_result)
}
