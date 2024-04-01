//! Governance utility functions

use namada_core::collections::HashMap;
use namada_governance::utils::TallyResult;
use namada_sdk::events::{Event, EventLevel, EventSegment, EventToEmit};
use thiserror::Error;

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

// TODO: move this to governance crate
pub mod event_types {
    //! Proposal event types.

    use std::borrow::Cow;

    use namada_sdk::events::{new_event_type_of, EventSegment, EventType};

    use super::ProposalEvent;

    /// Sub-domain of governance proposals.
    const PROPOSAL_SUBDOMAIN: &str = "proposal";

    /// Proposal rejected.
    pub const PROPOSAL_REJECTED: EventType =
        new_event_type_of::<ProposalEvent>(Cow::Borrowed({
            const SEGMENT: &[EventSegment] = &[
                EventSegment::new_static(PROPOSAL_SUBDOMAIN),
                EventSegment::new_static("rejected"),
            ];
            SEGMENT
        }));

    /// Proposal passed.
    pub const PROPOSAL_PASSED: EventType =
        new_event_type_of::<ProposalEvent>(Cow::Borrowed({
            const SEGMENT: &[EventSegment] = &[
                EventSegment::new_static(PROPOSAL_SUBDOMAIN),
                EventSegment::new_static("passed"),
            ];
            SEGMENT
        }));

    /// PGF steward proposal.
    pub const PROPOSAL_PGF_STEWARD: EventType =
        new_event_type_of::<ProposalEvent>(Cow::Borrowed({
            const SEGMENT: &[EventSegment] = &[
                EventSegment::new_static(PROPOSAL_SUBDOMAIN),
                EventSegment::new_static("pgf-steward"),
            ];
            SEGMENT
        }));

    /// PGF payments proposal.
    pub const PROPOSAL_PGF_PAYMENTS: EventType =
        new_event_type_of::<ProposalEvent>(Cow::Borrowed({
            const SEGMENT: &[EventSegment] = &[
                EventSegment::new_static(PROPOSAL_SUBDOMAIN),
                EventSegment::new_static("pgf-payments"),
            ];
            SEGMENT
        }));
}

/// Governance proposal event.
// TODO: move this to governance crate
pub struct ProposalEvent {
    /// ID of the governance proposal.
    pub id: u64,
    /// Governance proposal kind.
    pub kind: ProposalEventKind,
}

/// Proposal event kinds.
// TODO: move this to governance crate
pub enum ProposalEventKind {
    /// Governance proposal that has passed.
    Passed {
        /// Whether the proposal has WASM code to be executed or not.
        has_code: bool,
        /// The execution status of the proposal.
        execution_status: bool,
    },
    /// Governance proposal that has been rejected.
    Rejected,
    /// PGF steward governance proposal.
    PgfSteward {
        /// The outcome of the proposal.
        result: bool,
    },
    /// PGF payments governance proposal.
    PgfPayments {
        /// The outcome of the proposal.
        result: bool,
    },
}

impl From<ProposalEvent> for Event {
    fn from(proposal_event: ProposalEvent) -> Self {
        let ProposalEvent {
            id: proposal_id,
            kind,
        } = proposal_event;

        let (event_type, attributes) = match kind {
            ProposalEventKind::Passed {
                has_code,
                execution_status,
            } => (
                event_types::PROPOSAL_PASSED,
                governance_proposal_attributes(
                    TallyResult::Passed,
                    proposal_id,
                    has_code,
                    execution_status,
                ),
            ),
            ProposalEventKind::Rejected => (
                event_types::PROPOSAL_REJECTED,
                governance_proposal_attributes(
                    TallyResult::Rejected,
                    proposal_id,
                    false,
                    false,
                ),
            ),
            ProposalEventKind::PgfSteward { result } => (
                event_types::PROPOSAL_PGF_STEWARD,
                governance_proposal_attributes(
                    TallyResult::Passed,
                    proposal_id,
                    false,
                    result,
                ),
            ),
            ProposalEventKind::PgfPayments { result } => (
                event_types::PROPOSAL_PGF_PAYMENTS,
                governance_proposal_attributes(
                    TallyResult::Passed,
                    proposal_id,
                    false,
                    result,
                ),
            ),
        };

        Self {
            event_type,
            attributes,
            level: EventLevel::Block,
        }
    }
}

impl EventToEmit for ProposalEvent {
    const DOMAIN: EventSegment = EventSegment::new_static("governance");
}

impl ProposalEvent {
    /// Create a new proposal event for rejected proposal
    pub fn rejected_proposal_event(proposal_id: u64) -> Self {
        Self {
            id: proposal_id,
            kind: ProposalEventKind::Rejected,
        }
    }

    /// Create a new proposal event for default proposal
    pub fn default_proposal_event(
        proposal_id: u64,
        has_code: bool,
        execution_status: bool,
    ) -> Self {
        Self {
            id: proposal_id,
            kind: ProposalEventKind::Passed {
                has_code,
                execution_status,
            },
        }
    }

    /// Create a new proposal event for pgf stewards proposal
    pub fn pgf_steward_proposal_event(proposal_id: u64, result: bool) -> Self {
        Self {
            id: proposal_id,
            kind: ProposalEventKind::PgfSteward { result },
        }
    }

    /// Create a new proposal event for pgf payments proposal
    pub fn pgf_payments_proposal_event(proposal_id: u64, result: bool) -> Self {
        Self {
            id: proposal_id,
            kind: ProposalEventKind::PgfPayments { result },
        }
    }
}

/// Return the attributes of a governance proposal.
#[inline]
fn governance_proposal_attributes(
    tally: TallyResult,
    id: u64,
    has_proposal_code: bool,
    proposal_code_exit_status: bool,
) -> HashMap<String, String> {
    // TODO: switch to type-safe attributes api
    HashMap::from([
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
    ])
}
