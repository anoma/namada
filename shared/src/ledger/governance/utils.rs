//! Governance utility functions

use std::collections::{HashMap, HashSet};

use borsh::BorshDeserialize;
use namada_core::ledger::governance::cli::onchain::PgfAction;
use namada_core::ledger::governance::storage::proposal::{
    AddRemove, PGFAction, ProposalType,
};
use namada_core::ledger::governance::storage::vote::StorageProposalVote;
use namada_core::ledger::governance::utils::{TallyResult, VotePower};
use namada_proof_of_stake::{
    bond_amount, read_all_validator_addresses, read_pos_params,
    read_validator_stake,
};
use thiserror::Error;

use crate::core::ledger::governance::storage::keys as gov_storage;
use crate::ledger::events::EventType;
use crate::ledger::pos::BondId;
use crate::ledger::storage_api;
use crate::types::address::Address;
use crate::types::storage::Epoch;
use crate::types::token;

/// Proposal structure holding votes information necessary to compute the
/// outcome
pub struct Votes {
    /// Map from validators who voted to their total stake amount
    pub validators: HashMap<Address, (VotePower, StorageProposalVote)>,
    /// Map from delegation votes to their bond amount
    pub delegators:
        HashMap<Address, HashMap<Address, (VotePower, StorageProposalVote)>>,
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

    pub fn rejected_proposal_event(proposal_id: u64) -> Self {
        ProposalEvent::new(
            EventType::Proposal.to_string(),
            TallyResult::Rejected,
            proposal_id,
            false,
            false,
        )
    }

    pub fn default_proposal_event(
        proposal_id: u64,
        has_code: bool,
        execution_status: bool,
    ) -> Self {
        ProposalEvent::new(
            EventType::Proposal.to_string(),
            TallyResult::Passed,
            proposal_id,
            has_code,
            execution_status,
        )
    }

    pub fn pgf_steward_proposal_event(proposal_id: u64) -> Self {
        ProposalEvent::new(
            EventType::Proposal.to_string(),
            TallyResult::Passed,
            proposal_id,
            false,
            false,
        )
    }

    pub fn pgf_payments_proposal_event(proposal_id: u64) -> Self {
        ProposalEvent::new(
            EventType::Proposal.to_string(),
            TallyResult::Passed,
            proposal_id,
            false,
            false,
        )
    }

    pub fn eth_proposal_event(proposal_id: u64) -> Self {
        ProposalEvent::new(
            EventType::Proposal.to_string(),
            TallyResult::Passed,
            proposal_id,
            false,
            false,
        )
    }
}

enum ExpectedVote {
    /// The expected vote for the tally
    Expected,
    /// The opposite of the expected (e.g. Nay if expected is Yay)
    Opposite,
    /// Unexpected vote, i.e. a Yay vote carrying a wrong [`VoteType`]
    Wrong,
}

impl ExpectedVote {
    /// Get the inverse of an expected vote
    fn reverse(&mut self) {
        *self = match self {
            Self::Expected => Self::Opposite,
            Self::Opposite => Self::Expected,
            // A wrong vote inverse is still a wrong vote
            Self::Wrong => Self::Wrong,
        }
    }
}

fn expected_vote(
    proposal_type: &ProposalType,
    vote: &StorageProposalVote,
) -> ExpectedVote {
    let mut result = match vote {
        StorageProposalVote::Yay(t) if proposal_type == t => {
            ExpectedVote::Expected
        }
        StorageProposalVote::Yay(_) => ExpectedVote::Wrong,
        StorageProposalVote::Nay => ExpectedVote::Opposite,
    };

    // For PGF payment tally the Nay votes
    if let ProposalType::PGFPayment(_) = proposal_type {
        result.reverse();
    }

    result
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
    let vote_iter = storage_api::iter_prefix::<StorageProposalVote>(
        storage,
        &vote_prefix_key,
    )?;

    let mut validators_votes = HashMap::new();
    let mut delegators_votes: HashMap<
        Address,
        HashMap<Address, (VotePower, StorageProposalVote)>,
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
