//! Governance utility functions

use std::collections::HashMap;

use namada_governance::utils::TallyResult;
use namada_sdk::events::{Event, EventLevel};
use thiserror::Error;

use crate::ledger::events::EventType;

pub(super) enum ReadType {
    Pre,
    Post,
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

impl From<ProposalEvent> for Event {
    fn from(proposal_event: ProposalEvent) -> Self {
        Self {
            event_type: EventType::Proposal,
            level: EventLevel::Block,
            attributes: proposal_event.attributes,
        }
    }
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

    /// Create a new proposal event for rejected proposal
    pub fn rejected_proposal_event(proposal_id: u64) -> Self {
        ProposalEvent::new(
            EventType::Proposal.to_string(),
            TallyResult::Rejected,
            proposal_id,
            false,
            false,
        )
    }

    /// Create a new proposal event for default proposal
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

    /// Create a new proposal event for pgf stewards proposal
    pub fn pgf_steward_proposal_event(proposal_id: u64, result: bool) -> Self {
        ProposalEvent::new(
            EventType::Proposal.to_string(),
            TallyResult::Passed,
            proposal_id,
            false,
            result,
        )
    }

    /// Create a new proposal event for pgf payments proposal
    pub fn pgf_payments_proposal_event(proposal_id: u64, result: bool) -> Self {
        ProposalEvent::new(
            EventType::Proposal.to_string(),
            TallyResult::Passed,
            proposal_id,
            false,
            result,
        )
    }

    /// Create a new proposal event for eth proposal
    pub fn eth_proposal_event(proposal_id: u64, result: bool) -> Self {
        ProposalEvent::new(
            EventType::Proposal.to_string(),
            TallyResult::Passed,
            proposal_id,
            false,
            result,
        )
    }
}
