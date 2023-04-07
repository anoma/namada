//! Governance utility functions

use std::collections::HashMap;

use borsh::BorshDeserialize;
use namada_core::types::governance::ProposalResult;
use namada_core::types::transaction::governance::ProposalType;
use namada_proof_of_stake::{
    bond_amount, read_all_validator_addresses, read_pos_params,
    read_validator_stake,
};
use thiserror::Error;

use crate::ledger::governance::storage as gov_storage;
use crate::ledger::pos::BondId;
use crate::ledger::storage_api;
use crate::types::address::Address;
use crate::types::governance::{
    ProposalVote, TallyResult, VotePower, VoteType,
};
use crate::types::storage::Epoch;
use crate::types::token;

/// Proposal structure holding votes information necessary to compute the
/// outcome
pub struct Votes {
    /// Map from validators who voted to their total stake amount
    pub validators: HashMap<Address, (VotePower, ProposalVote)>,
    /// Map from delegation votes to their bond amount
    pub delegators:
        HashMap<Address, HashMap<Address, (VotePower, ProposalVote)>>,
}

/// Proposal errors
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid validator set deserialization
    #[error("Invalid validator set")]
    InvalidValidatorSet,
    /// Invalid proposal field deserialization
    #[error("Invalid proposal {0}")]
    InvalidProposal(u64),
    /// Error during tally
    #[error("Error while tallying proposal: {0}")]
    Tally(String),
}

/// Proposal event definition
pub struct ProposalEvent {
    /// Proposal event type
    pub event_type: String,
    /// Proposal event attributes
    pub attributes: HashMap<String, String>,
}

impl ProposalEvent {
    /// Create a proposal event
    pub fn new(
        event_type: String,
        tally: TallyResult,
        id: u64,
        has_proposal_code: bool,
        proposal_code_exit_status: bool,
    ) -> Self {
        let attributes = HashMap::from([
            ("tally_result".to_string(), tally.to_string()),
            ("proposal_id".to_string(), id.to_string()),
            (
                "has_proposal_code".to_string(),
                (!has_proposal_code as u64).to_string(),
            ),
            (
                "proposal_code_exit_status".to_string(),
                (!proposal_code_exit_status as u64).to_string(),
            ),
        ]);
        Self {
            event_type,
            attributes,
        }
    }
}

/// Return a proposal result
pub fn compute_tally(
    votes: Votes,
    total_stake: VotePower,
    proposal_type: ProposalType,
) -> Result<ProposalResult, Error> {
    // FIXME: update specs

    match proposal_type {
        ProposalType::Default(_) => {
            let total_staked_voted =
                dispatch_normal_tally(votes, &proposal_type);
            Ok(threshold_tally(
                proposal_type,
                total_staked_voted,
                total_stake,
                2,
                3,
            ))
        }
        ProposalType::ETHBridge => {
            let total_staked_voted = dispatch_eth_tally(votes);
            Ok(threshold_tally(
                proposal_type,
                total_staked_voted,
                total_stake,
                2,
                3,
            ))
        }
        ProposalType::PGFSteward(_) => {
            let total_staked_voted =
                dispatch_normal_tally(votes, &proposal_type);
            Ok(threshold_tally(
                proposal_type,
                total_staked_voted,
                total_stake,
                1,
                3,
            ))
        }
        ProposalType::PGFPayment(_) => {
            let total_staked_voted = dispatch_pgf_actions_tally(votes);
            Ok(threshold_tally(
                proposal_type,
                total_staked_voted,
                total_stake,
                2,
                3,
            ))
        }
    }
}

fn threshold_tally(
    proposal_type: ProposalType,
    total_staked_voted: VotePower,
    total_stake: VotePower,
    num: u128,
    denum: u128,
) -> ProposalResult {
    // Proposal passes if threshold of total voting power voted the desired vote
    if total_staked_voted >= (total_stake / denum) * num {
        ProposalResult {
            result: TallyResult::Passed(proposal_type.into()),
            total_voting_power: total_stake,
            total_yay_power: total_staked_voted,
            total_nay_power: 0,
        }
    } else {
        ProposalResult {
            result: TallyResult::Rejected,
            total_voting_power: total_stake,
            total_yay_power: total_staked_voted,
            total_nay_power: 0,
        }
    }
}

fn dispatch_normal_tally(
    votes: Votes,
    proposal_type: &ProposalType,
) -> VotePower {
    let Votes {
        validators,
        delegators,
    } = votes;

    let mut total_yay_staked_tokens = VotePower::default();

    for (_, (amount, validator_vote)) in validators.iter() {
        match validator_vote {
            ProposalVote::Yay(vote_type) if proposal_type == vote_type => {
                total_yay_staked_tokens += amount
            }
            _ => {
                // Log the error and continue
                tracing::error!(
                    "Unexpected vote type. Expected: {}, Found: {}",
                    proposal_type,
                    validator_vote
                );
                continue;
            }
        }
    }

    for (_, vote_map) in delegators.iter() {
        for (validator_address, (vote_power, delegator_vote)) in vote_map.iter()
        {
            match delegator_vote {
                ProposalVote::Yay(vote_type) if proposal_type == vote_type => {
                    if !validators.contains_key(validator_address) {
                        // YAY: Add delegator amount whose validator
                        // didn't vote / voted nay
                        total_yay_staked_tokens += vote_power;
                    }
                }
                ProposalVote::Nay => {
                    // NAY: Remove delegator amount whose validator
                    // validator vote yay
                    if validators.contains_key(validator_address) {
                        total_yay_staked_tokens -= vote_power;
                    }
                }

                _ => {
                    // Log the error and continue
                    tracing::error!(
                        "Unexpected vote type. Expected: {}, Found: {}",
                        proposal_type,
                        delegator_vote
                    );
                    continue;
                }
            }
        }
    }

    total_yay_staked_tokens
}

fn dispatch_eth_tally(votes: Votes) -> VotePower {
    let Votes {
        validators,
        delegators: _,
    } = votes;

    let mut total_yay_staked_tokens = VotePower::default();

    // Only validators are allowed to vote
    for (_, (amount, validator_vote)) in validators.iter() {
        if let ProposalVote::Yay(VoteType::ETHBridge(_)) = validator_vote {
            total_yay_staked_tokens += amount;
        }
    }

    total_yay_staked_tokens
}

fn dispatch_pgf_actions_tally(votes: Votes) -> VotePower {
    let Votes {
        validators,
        delegators,
    } = votes;

    let mut total_nay_staked_tokens = VotePower::default();

    for (_, (amount, validator_vote)) in validators.iter() {
        if let ProposalVote::Nay = validator_vote {
            total_nay_staked_tokens += amount;
        }
    }

    for (_, vote_map) in delegators.iter() {
        for (validator_address, (vote_power, delegator_vote)) in vote_map.iter()
        {
            match delegator_vote {
                ProposalVote::Yay(VoteType::PGFPayment) => {
                    // YAY: Remove delegator amount whose validator voted nay or
                    // didn't vote
                    match validators.get(validator_address) {
                        Some((_, vote)) => {
                            if !vote.is_yay() {
                                total_nay_staked_tokens -= vote_power;
                            }
                        }
                        None => total_nay_staked_tokens -= vote_power,
                    }
                }
                ProposalVote::Nay => {
                    // NAY: Remove delegator amount whose validator
                    // validator vote yay
                    match validators.get(validator_address) {
                        Some((_, vote)) => {
                            if vote.is_yay() {
                                total_nay_staked_tokens += vote_power;
                            }
                        }
                        None => total_nay_staked_tokens += vote_power,
                    }
                }

                _ => {
                    // Log the error and continue
                    tracing::error!(
                        "Unexpected vote type. Expected: {}, Found: {}",
                        ProposalType::PGFPayment(vec![]),
                        delegator_vote
                    );
                    continue;
                }
            }
        }
    }

    total_nay_staked_tokens
}

/// Prepare Votes structure to compute proposal tally
pub fn get_proposal_votes<S>(
    storage: &S,
    epoch: Epoch,
    proposal_id: u64,
) -> storage_api::Result<Votes>
where
    S: storage_api::StorageRead,
{
    let params = read_pos_params(storage)?;
    let validators = read_all_validator_addresses(storage, epoch)?;

    let vote_prefix_key =
        gov_storage::get_proposal_vote_prefix_key(proposal_id);
    let vote_iter =
        storage_api::iter_prefix::<ProposalVote>(storage, &vote_prefix_key)?;

    let mut validators_votes = HashMap::new();
    let mut delegators_votes: HashMap<
        Address,
        HashMap<Address, (VotePower, ProposalVote)>,
    > = HashMap::new();

    for next_vote in vote_iter {
        let (vote_key, vote) = next_vote?;
        let voter_address = gov_storage::get_voter_address(&vote_key);
        match voter_address {
            Some(voter_address) => {
                if validators.contains(voter_address) {
                    let amount: VotePower = read_validator_stake(
                        storage,
                        &params,
                        voter_address,
                        epoch,
                    )?
                    .unwrap_or_default()
                    .into();

                    validators_votes
                        .insert(voter_address.clone(), (amount, vote));
                } else if !validators.contains(voter_address) {
                    let validator_address =
                        gov_storage::get_vote_delegation_address(&vote_key);
                    match validator_address {
                        Some(validator) => {
                            let bond_id = BondId {
                                source: voter_address.clone(),
                                validator: validator.clone(),
                            };
                            let amount =
                                bond_amount(storage, &params, &bond_id, epoch)?
                                    .1;

                            if amount != token::Amount::default() {
                                let entry = delegators_votes
                                    .entry(voter_address.to_owned())
                                    .or_default();
                                entry.insert(
                                    validator.to_owned(),
                                    (VotePower::from(amount), vote),
                                );
                            }
                        }
                        None => continue,
                    }
                }
            }
            None => continue,
        }
    }

    Ok(Votes {
        validators: validators_votes,
        delegators: delegators_votes,
    })
}

/// Calculate the valid voting window for validator given a proposal epoch
/// details
pub fn is_valid_validator_voting_period(
    current_epoch: Epoch,
    voting_start_epoch: Epoch,
    voting_end_epoch: Epoch,
) -> bool {
    voting_start_epoch < voting_end_epoch
        && current_epoch * 3 <= voting_start_epoch + voting_end_epoch * 2
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
                gov_storage::get_proposal_execution_key(id);
            storage.has_key(&proposal_execution_key)
        }
        None => Ok(false),
    }
}
