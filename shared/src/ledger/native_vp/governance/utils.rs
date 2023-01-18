//! Governance utility functions

use std::collections::HashMap;

use borsh::BorshDeserialize;
use namada_core::types::transaction::governance::ProposalType;
use namada_proof_of_stake::{
    bond_amount, read_all_validator_addresses, read_pos_params,
    read_total_stake, read_validator_stake,
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
    /// Map from validators who votes yay to their total stake amount
    pub yay_validators: HashMap<Address, (VotePower, ProposalVote)>,
    /// Map from delegation who votes yay to their bond amount
    pub yay_delegators:
        HashMap<Address, HashMap<Address, (VotePower, ProposalVote)>>,
    /// Map from delegation who votes nay to their bond amount
    pub nay_delegators:
        HashMap<Address, HashMap<Address, (VotePower, ProposalVote)>>,
}
//FIXME: since I attach the vote, can I use only two field, one for the validators and one for the delegators?

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

pub enum Tally {
    //FIXME: can join this with TallyResult?
    Default(bool),
    PGFCouncil(Option<(Address, u64)>),
}

/// Return a proposal result
pub fn compute_tally<S>(
    storage: &S,
    epoch: Epoch,
    votes: Votes,
    proposal_type: &ProposalType,
) -> storage_api::Result<Tally>
where
    S: storage_api::StorageRead,
{
    let params = read_pos_params(storage)?;
    let total_stake = read_total_stake(storage, &params, epoch)?;
    let total_stake = VotePower::from(u64::from(total_stake));

    let Votes {
        yay_validators,
        yay_delegators,
        nay_delegators,
    } = votes;

    match proposal_type {
        ProposalType::Default(_) => {
            let mut total_yay_staked_tokens = VotePower::from(0u64);
            for (_, (amount, validator_vote)) in yay_validators.iter() {
                if let ProposalVote::Yay(VoteType::Default) = validator_vote {
                    total_yay_staked_tokens += amount;
                } else {
                    return Err(storage_api::Error::SimpleMessage(
                        "Unexpected vote type",
                    ));
                }
            }

            // YAY: Add delegator amount whose validator didn't vote / voted nay
            for (_, vote_map) in yay_delegators.iter() {
                for (validator_address, (vote_power, delegator_vote)) in
                    vote_map.iter()
                {
                    if let ProposalVote::Yay(VoteType::Default) = delegator_vote
                    {
                        if !yay_validators.contains_key(validator_address) {
                            total_yay_staked_tokens += vote_power;
                        }
                    } else {
                        return Err(storage_api::Error::SimpleMessage(
                            "Unexpected vote type",
                        ));
                    }
                }
            }

            // NAY: Remove delegator amount whose validator validator vote yay
            for (_, vote_map) in nay_delegators.iter() {
                for (validator_address, (vote_power, delegator_vote)) in
                    vote_map.iter()
                {
                    if let ProposalVote::Nay = delegator_vote {
                        if yay_validators.contains_key(validator_address) {
                            total_yay_staked_tokens -= vote_power;
                        }
                    } else {
                        return Err(storage_api::Error::SimpleMessage(
                            "Unexpected vote type",
                        ));
                    }
                }
            }

            Ok(Tally::Default(
                total_yay_staked_tokens >= 2 / 3 * total_stake,
            ))
        }
        ProposalType::PGFCouncil => {
            let mut total_yay_staked_tokens = HashMap::new();
            for (_, (amount, vote)) in yay_validators.iter() {
                if let ProposalVote::Yay(VoteType::PGFCouncil(votes)) = vote {
                    for v in votes {
                        *total_yay_staked_tokens.entry(v).or_insert(0) +=
                            amount;
                    }
                } else {
                    return Err(storage_api::Error::SimpleMessage(
                        "Unexpected vote type",
                    ));
                }
            }

            // YAY: Add delegator amount whose validator didn't vote / voted nay or adjust voting power
            // if delegator voted yay with a different memo
            for (_, vote_map) in yay_delegators.iter() {
                for (validator_address, (vote_power, delegator_vote)) in
                    vote_map.iter()
                {
                    if let ProposalVote::Yay(VoteType::PGFCouncil(
                        delegator_votes,
                    )) = delegator_vote
                    {
                        match yay_validators.get(validator_address) {
                            Some((_, validator_vote)) => {
                                if let ProposalVote::Yay(
                                    VoteType::PGFCouncil(validator_votes),
                                ) = validator_vote
                                {
                                    for vote in validator_votes
                                        .symmetric_difference(delegator_votes)
                                    {
                                        if validator_votes.contains(vote) {
                                            // Delegator didn't vote for this, reduce voting power
                                            if let Some(power) =
                                                total_yay_staked_tokens
                                                    .get_mut(vote)
                                            {
                                                *power -= vote_power;
                                            } else {
                                                return Err(storage_api::Error::SimpleMessage("Expected PGF vote was not in tally"));
                                            }
                                        } else {
                                            // Validator didn't vote for this, add voting power
                                            *total_yay_staked_tokens
                                                .entry(vote)
                                                .or_insert(0) += vote_power;
                                        }
                                    }
                                } else {
                                    return Err(
                                        storage_api::Error::SimpleMessage(
                                            "Unexpected vote type",
                                        ),
                                    );
                                }
                            }
                            None => {
                                // Validator didn't vote or voted nay, add delegator vote

                                for vote in delegator_votes {
                                    *total_yay_staked_tokens
                                        .entry(vote)
                                        .or_insert(0) += vote_power;
                                }
                            }
                        }
                    } else {
                        return Err(storage_api::Error::SimpleMessage(
                            "Unexpected vote type",
                        ));
                    }
                }
            }

            // NAY: Remove delegator amount whose validator voted yay
            for (_, vote_map) in nay_delegators.iter() {
                for (validator_address, (vote_power, _delegator_vote)) in
                    vote_map.iter()
                {
                    if yay_validators.contains_key(validator_address) {
                        for (_, validator_vote) in
                            yay_validators.get(validator_address)
                        {
                            if let ProposalVote::Yay(VoteType::PGFCouncil(
                                votes,
                            )) = validator_vote
                            {
                                for vote in votes {
                                    if let Some(power) =
                                        total_yay_staked_tokens.get_mut(vote)
                                    {
                                        *power -= vote_power;
                                    } else {
                                        return Err(storage_api::Error::SimpleMessage("Expected PGF vote was not in tally"));
                                    }
                                }
                            } else {
                                return Err(storage_api::Error::SimpleMessage(
                                    "Unexpected vote type",
                                ));
                            }
                        }
                    }
                }
            }

            // At least 1/3 of the total voting power must vote Yay
            let total_voted_power = total_yay_staked_tokens
                .iter()
                .fold(0, |acc, (_, vote_power)| acc + vote_power);

            if total_voted_power >= 1 / 3 * total_stake {
                // Select the winner council based on simple majority
                Ok(Tally::PGFCouncil(
                    total_yay_staked_tokens
                        .into_iter()
                        .max_by(|a, b| a.1.cmp(&b.1))
                        .map_or(None, |(vote, _)| Some(vote.to_owned())),
                ))
            } else {
                Ok(Tally::PGFCouncil(None))
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
    let mut yay_delegators: HashMap<
        Address,
        HashMap<Address, (VotePower, ProposalVote)>,
    > = HashMap::new();
    let mut nay_delegators: HashMap<
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
                                if vote.is_yay() {
                                    let entry = yay_delegators
                                        .entry(voter_address.to_owned())
                                        .or_default();
                                    entry.insert(
                                        validator.to_owned(),
                                        (VotePower::from(amount), vote),
                                    );
                                } else {
                                    let entry = nay_delegators
                                        .entry(voter_address.to_owned())
                                        .or_default();
                                    entry.insert(
                                        validator.to_owned(),
                                        (VotePower::from(amount), vote),
                                    );
                                }
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
        yay_delegators,
        nay_delegators,
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
