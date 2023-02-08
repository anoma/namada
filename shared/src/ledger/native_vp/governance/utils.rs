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
    ProposalVote, Tally, TallyResult, VotePower, VoteType,
};
use crate::types::storage::Epoch;
use crate::types::token;

/// Proposal structure holding votes information necessary to compute the
/// outcome
pub struct Votes {
    /// Map from validators who votes yay to their total stake amount
    pub yay_validators: HashMap<Address, (VotePower, ProposalVote)>,
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
    proposal_type: &ProposalType,
) -> ProposalResult {
    let Votes {
        yay_validators,
        delegators,
    } = votes;

    match proposal_type {
        ProposalType::Default(_) | ProposalType::ETHBridge => {
            let mut total_yay_staked_tokens = VotePower::default();

            for (_, (amount, validator_vote)) in yay_validators.iter() {
                if let ProposalVote::Yay(vote_type) = validator_vote {
                    if proposal_type == vote_type {
                        total_yay_staked_tokens += amount;
                    } else {
                        // Log the error and continue
                        tracing::error!(
                            "Unexpected vote type. Expected: {}, Found: {}",
                            proposal_type,
                            validator_vote
                        );
                        continue;
                    }
                } else {
                    // Log the error and continue
                    tracing::error!(
                        "Unexpected vote type. Expected: {}, Found: {}",
                        proposal_type,
                        validator_vote
                    );
                    continue;
                }
            }

            // This loop is taken only for Default proposals
            for (_, vote_map) in delegators.iter() {
                for (validator_address, (vote_power, delegator_vote)) in
                    vote_map.iter()
                {
                    match delegator_vote {
                        ProposalVote::Yay(VoteType::Default) => {
                            if !yay_validators.contains_key(validator_address) {
                                // YAY: Add delegator amount whose validator
                                // didn't vote / voted nay
                                total_yay_staked_tokens += vote_power;
                            }
                        }
                        ProposalVote::Nay => {
                            // NAY: Remove delegator amount whose validator
                            // validator vote yay

                            if yay_validators.contains_key(validator_address) {
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

            // Proposal passes if 2/3 of total voting power voted Yay
            if total_yay_staked_tokens >= (total_stake / 3) * 2 {
                let tally_result = match proposal_type {
                    ProposalType::Default(_) => {
                        TallyResult::Passed(Tally::Default)
                    }
                    ProposalType::ETHBridge => {
                        TallyResult::Passed(Tally::ETHBridge)
                    }
                    _ => TallyResult::Failed(format!(
                        "Unexpected proposal type {}",
                        proposal_type
                    )),
                };

                ProposalResult {
                    result: tally_result,
                    total_voting_power: total_stake,
                    total_yay_power: total_yay_staked_tokens,
                    total_nay_power: 0,
                }
            } else {
                ProposalResult {
                    result: TallyResult::Rejected,
                    total_voting_power: total_stake,
                    total_yay_power: total_yay_staked_tokens,
                    total_nay_power: 0,
                }
            }
        }
        ProposalType::PGFCouncil => {
            let mut total_yay_staked_tokens = HashMap::new();
            for (_, (amount, validator_vote)) in yay_validators.iter() {
                if let ProposalVote::Yay(VoteType::PGFCouncil(votes)) =
                    validator_vote
                {
                    for v in votes {
                        *total_yay_staked_tokens.entry(v).or_insert(0) +=
                            amount;
                    }
                } else {
                    // Log the error and continue
                    tracing::error!(
                        "Unexpected vote type. Expected: PGFCouncil, Found: {}",
                        validator_vote
                    );
                    continue;
                }
            }

            // YAY: Add delegator amount whose validator didn't vote / voted nay
            // or adjust voting power if delegator voted yay with a
            // different memo
            for (_, vote_map) in delegators.iter() {
                for (validator_address, (vote_power, delegator_vote)) in
                    vote_map.iter()
                {
                    match delegator_vote {
                        ProposalVote::Yay(VoteType::PGFCouncil(
                            delegator_votes,
                        )) => {
                            match yay_validators.get(validator_address) {
                                Some((_, validator_vote)) => {
                                    if let ProposalVote::Yay(
                                        VoteType::PGFCouncil(validator_votes),
                                    ) = validator_vote
                                    {
                                        for vote in validator_votes
                                            .symmetric_difference(
                                                delegator_votes,
                                            )
                                        {
                                            if validator_votes.contains(vote) {
                                                // Delegator didn't vote for
                                                // this, reduce voting power
                                                if let Some(power) =
                                                    total_yay_staked_tokens
                                                        .get_mut(vote)
                                                {
                                                    *power -= vote_power;
                                                } else {
                                                    return ProposalResult {
                                                    result: TallyResult::Failed(format!("Expected PGF vote {:?} was not in tally", vote)),
                                                    total_voting_power: total_stake,
                                                    total_yay_power: 0,
                                                    total_nay_power: 0};
                                                }
                                            } else {
                                                // Validator didn't vote for
                                                // this, add voting power
                                                *total_yay_staked_tokens
                                                    .entry(vote)
                                                    .or_insert(0) += vote_power;
                                            }
                                        }
                                    } else {
                                        // Log the error and continue
                                        tracing::error!(
                        "Unexpected vote type. Expected: PGFCouncil, Found: {}",
                        validator_vote
                    );
                                        continue;
                                    }
                                }
                                None => {
                                    // Validator didn't vote or voted nay, add
                                    // delegator vote

                                    for vote in delegator_votes {
                                        *total_yay_staked_tokens
                                            .entry(vote)
                                            .or_insert(0) += vote_power;
                                    }
                                }
                            }
                        }
                        ProposalVote::Nay => {
                            for (
                                validator_address,
                                (vote_power, _delegator_vote),
                            ) in vote_map.iter()
                            {
                                if let Some((_, validator_vote)) =
                                    yay_validators.get(validator_address)
                                {
                                    if let ProposalVote::Yay(
                                        VoteType::PGFCouncil(votes),
                                    ) = validator_vote
                                    {
                                        for vote in votes {
                                            if let Some(power) =
                                                total_yay_staked_tokens
                                                    .get_mut(vote)
                                            {
                                                *power -= vote_power;
                                            } else {
                                                return ProposalResult {
                                                    result: TallyResult::Failed(
                                                        format!(
                                                            "Expected PGF \
                                                             vote {:?} was \
                                                             not in tally",
                                                            vote
                                                        ),
                                                    ),
                                                    total_voting_power:
                                                        total_stake,
                                                    total_yay_power: 0,
                                                    total_nay_power: 0,
                                                };
                                            }
                                        }
                                    } else {
                                        // Log the error and continue
                                        tracing::error!(
                        "Unexpected vote type. Expected: PGFCouncil, Found: {}",
                        validator_vote
                    );
                                        continue;
                                    }
                                }
                            }
                        }
                        _ => {
                            // Log the error and continue
                            tracing::error!(
                        "Unexpected vote type. Expected: PGFCouncil, Found: {}",
                        delegator_vote
                    );
                            continue;
                        }
                    }
                }
            }

            // At least 1/3 of the total voting power must vote Yay
            let total_yay_voted_power = total_yay_staked_tokens
                .iter()
                .fold(0, |acc, (_, vote_power)| acc + vote_power);

            match total_yay_voted_power.checked_mul(3) {
                Some(v) if v < total_stake => ProposalResult {
                    result: TallyResult::Rejected,
                    total_voting_power: total_stake,
                    total_yay_power: total_yay_voted_power,
                    total_nay_power: 0,
                },
                _ => {
                    // Select the winner council based on approval voting
                    // (majority)
                    let council = total_yay_staked_tokens
                        .into_iter()
                        .max_by(|a, b| a.1.cmp(&b.1))
                        .map(|(vote, _)| vote.to_owned())
                        .unwrap(); // Cannot be None at this point

                    ProposalResult {
                        result: TallyResult::Passed(Tally::PGFCouncil(council)),
                        total_voting_power: total_stake,
                        total_yay_power: total_yay_voted_power,
                        total_nay_power: 0,
                    }
                }
            }
        }
    }
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

    let mut yay_validators = HashMap::new();
    let mut delegators: HashMap<
        Address,
        HashMap<Address, (VotePower, ProposalVote)>,
    > = HashMap::new();

    for next_vote in vote_iter {
        let (vote_key, vote) = next_vote?;
        let voter_address = gov_storage::get_voter_address(&vote_key);
        match voter_address {
            Some(voter_address) => {
                if vote.is_yay() && validators.contains(voter_address) {
                    let amount: VotePower = read_validator_stake(
                        storage,
                        &params,
                        voter_address,
                        epoch,
                    )?
                    .unwrap_or_default()
                    .into();

                    yay_validators
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
                                let entry = delegators
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
        yay_validators,
        delegators,
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
