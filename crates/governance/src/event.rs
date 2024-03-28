//! Governance transaction events.

use std::collections::BTreeMap;

use namada_events::extend::{EventAttributeEntry, ExtendAttributesMap};
use namada_events::{Event, EventLevel, EventToEmit};

use crate::utils::TallyResult as GovTallyResult;

pub mod types {
    //! Governance event types.

    use namada_events::EventType;

    use super::ProposalEvent;

    /// Sub-domain of governance proposals.
    const PROPOSAL_SUBDOMAIN: &str = "proposal";

    /// Proposal rejected.
    pub const PROPOSAL_REJECTED: EventType = namada_events::event_type!(
        ProposalEvent,
        PROPOSAL_SUBDOMAIN,
        "rejected"
    );

    /// Proposal passed.
    pub const PROPOSAL_PASSED: EventType =
        namada_events::event_type!(ProposalEvent, PROPOSAL_SUBDOMAIN, "passed");

    /// PGF steward proposal.
    pub const PROPOSAL_PGF_STEWARD: EventType = namada_events::event_type!(
        ProposalEvent,
        PROPOSAL_SUBDOMAIN,
        "pgf-steward"
    );

    /// PGF payments proposal.
    pub const PROPOSAL_PGF_PAYMENTS: EventType = namada_events::event_type!(
        ProposalEvent,
        PROPOSAL_SUBDOMAIN,
        "pgf-payments"
    );

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_gov_event_type_as_str() {
            assert_eq!(&*PROPOSAL_PASSED, "governance/proposal/passed");
        }
    }
}

/// Governance proposal event.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ProposalEvent {
    /// ID of the governance proposal.
    pub id: u64,
    /// Governance proposal kind.
    pub kind: ProposalEventKind,
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

/// Proposal event kinds.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
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
                types::PROPOSAL_PASSED,
                governance_proposal_attributes(
                    GovTallyResult::Passed,
                    proposal_id,
                    has_code,
                    execution_status,
                ),
            ),
            ProposalEventKind::Rejected => (
                types::PROPOSAL_REJECTED,
                governance_proposal_attributes(
                    GovTallyResult::Rejected,
                    proposal_id,
                    false,
                    false,
                ),
            ),
            ProposalEventKind::PgfSteward { result } => (
                types::PROPOSAL_PGF_STEWARD,
                governance_proposal_attributes(
                    GovTallyResult::Passed,
                    proposal_id,
                    false,
                    result,
                ),
            ),
            ProposalEventKind::PgfPayments { result } => (
                types::PROPOSAL_PGF_PAYMENTS,
                governance_proposal_attributes(
                    GovTallyResult::Passed,
                    proposal_id,
                    false,
                    result,
                ),
            ),
        };

        let mut event = Self::new(event_type, EventLevel::Block);

        #[allow(deprecated)]
        {
            *event.attributes_mut() = attributes;
        }

        event
    }
}

/// Return the attributes of a governance proposal.
#[inline]
fn governance_proposal_attributes(
    tally: GovTallyResult,
    id: u64,
    has_proposal_code: bool,
    proposal_code_exit_status: bool,
) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    attrs
        .with_attribute(TallyResult(tally))
        .with_attribute(ProposalId(id))
        .with_attribute(HasProposalCode(has_proposal_code))
        .with_attribute(ProposalCodeExitStatus(proposal_code_exit_status));
    attrs
}

impl EventToEmit for ProposalEvent {
    const DOMAIN: &'static str = "governance";
}

/// Extend an [`Event`] with tally result data.
pub struct TallyResult(pub GovTallyResult);

impl EventAttributeEntry<'static> for TallyResult {
    type Value = GovTallyResult;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "tally_result";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with proposal id data.
pub struct ProposalId(pub u64);

impl EventAttributeEntry<'static> for ProposalId {
    type Value = u64;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "proposal_id";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with has proposal code data.
pub struct HasProposalCode(pub bool);

impl EventAttributeEntry<'static> for HasProposalCode {
    type Value = bool;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "has_proposal_code";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with proposal code exit status data.
pub struct ProposalCodeExitStatus(pub bool);

impl EventAttributeEntry<'static> for ProposalCodeExitStatus {
    type Value = bool;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "proposal_code_exit_status";

    fn into_value(self) -> Self::Value {
        self.0
    }
}
