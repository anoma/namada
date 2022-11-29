use std::collections::HashMap;
use std::str::FromStr;

use borsh::BorshDeserialize;
use namada_proof_of_stake::PosReadOnly;
use thiserror::Error;

use crate::ledger::governance::storage as gov_storage;
use crate::ledger::pos::BondId;
use crate::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use crate::ledger::storage_api;
use crate::types::address::Address;
use crate::types::governance::{ProposalVote, TallyResult, VotePower};
use crate::types::storage::{Epoch, Key};
use crate::types::token;

/// Proposal structure holding votes information necessary to compute the
/// outcome
pub struct Votes {
    /// Map from validators who votes yay to their total stake amount
    pub yay_validators: HashMap<Address, VotePower>,
    /// Map from delegation who votes yay to their bond amount
    pub yay_delegators: HashMap<Address, HashMap<Address, VotePower>>,
    /// Map from delegation who votes nay to their bond amount
    pub nay_delegators: HashMap<Address, HashMap<Address, VotePower>>,
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

/// Return a proposal result - accepted only when the result is `Ok(true)`.
pub fn compute_tally<D, H>(
    storage: &Storage<D, H>,
    epoch: Epoch,
    votes: Votes,
) -> storage_api::Result<bool>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let total_stake: VotePower = storage.total_stake(epoch)?.into();

    let Votes {
        yay_validators,
        yay_delegators,
        nay_delegators,
    } = votes;

    let mut total_yay_staked_tokens = VotePower::from(0_u64);
    for (_, amount) in yay_validators.clone().into_iter() {
        total_yay_staked_tokens += amount;
    }

    // YAY: Add delegator amount whose validator didn't vote / voted nay
    for (_, vote_map) in yay_delegators.iter() {
        for (validator_address, vote_power) in vote_map.iter() {
            if !yay_validators.contains_key(validator_address) {
                total_yay_staked_tokens += vote_power;
            }
        }
    }

    // NAY: Remove delegator amount whose validator validator vote yay
    for (_, vote_map) in nay_delegators.iter() {
        for (validator_address, vote_power) in vote_map.iter() {
            if yay_validators.contains_key(validator_address) {
                total_yay_staked_tokens -= vote_power;
            }
        }
    }

    Ok(3 * total_yay_staked_tokens >= 2 * total_stake)
}

/// Prepare Votes structure to compute proposal tally
pub fn get_proposal_votes<D, H>(
    storage: &Storage<D, H>,
    epoch: Epoch,
    proposal_id: u64,
) -> storage_api::Result<Votes>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let validators = storage.validator_addresses(epoch)?;

    let vote_prefix_key =
        gov_storage::get_proposal_vote_prefix_key(proposal_id);
    let (vote_iter, _) = storage.iter_prefix(&vote_prefix_key);

    let mut yay_validators = HashMap::new();
    let mut yay_delegators: HashMap<Address, HashMap<Address, VotePower>> =
        HashMap::new();
    let mut nay_delegators: HashMap<Address, HashMap<Address, VotePower>> =
        HashMap::new();

    for (key, vote_bytes, _) in vote_iter {
        let vote_key = Key::from_str(key.as_str()).ok();
        let vote = ProposalVote::try_from_slice(&vote_bytes[..]).ok();
        match (vote_key, vote) {
            (Some(key), Some(vote)) => {
                let voter_address = gov_storage::get_voter_address(&key);
                match voter_address {
                    Some(voter_address) => {
                        if vote.is_yay() && validators.contains(voter_address) {
                            let amount: VotePower = storage
                                .validator_stake(voter_address, epoch)?
                                .into();
                            yay_validators
                                .insert(voter_address.clone(), amount);
                        } else if !validators.contains(voter_address) {
                            let validator_address =
                                gov_storage::get_vote_delegation_address(&key);
                            match validator_address {
                                Some(validator) => {
                                    let bond_id = BondId {
                                        source: voter_address.clone(),
                                        validator: validator.clone(),
                                    };
                                    let amount =
                                        storage.bond_amount(&bond_id, epoch)?;
                                    if amount != token::Amount::default() {
                                        if vote.is_yay() {
                                            let entry = yay_delegators
                                                .entry(voter_address.to_owned())
                                                .or_default();
                                            entry.insert(
                                                validator.to_owned(),
                                                VotePower::from(amount),
                                            );
                                        } else {
                                            let entry = nay_delegators
                                                .entry(voter_address.to_owned())
                                                .or_default();
                                            entry.insert(
                                                validator.to_owned(),
                                                VotePower::from(amount),
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
            _ => continue,
        }
    }

    Ok(Votes {
        yay_validators,
        yay_delegators,
        nay_delegators,
    })
}
