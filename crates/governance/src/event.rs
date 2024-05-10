//! Governance transaction events.

use std::collections::BTreeMap;

use namada_events::extend::{EventAttributeEntry, ExtendAttributesMap};
use namada_events::{Event, EventLevel, EventToEmit};

use crate::utils::TallyResult as GovTallyResult;
use crate::ProposalType as GovProposalType;

pub mod types {
    //! Governance event types.

    use namada_events::EventType;

    use super::GovernanceEvent;

    /// Sub-domain of governance proposals.
    const PROPOSAL_SUBDOMAIN: &str = "proposal";

    /// Proposal rejected.
    pub const PROPOSAL_REJECTED: EventType = namada_events::event_type!(
        GovernanceEvent,
        PROPOSAL_SUBDOMAIN,
        "rejected"
    );

    /// Proposal passed.
    pub const PROPOSAL_PASSED: EventType = namada_events::event_type!(
        GovernanceEvent,
        PROPOSAL_SUBDOMAIN,
        "passed"
    );

    /// New proposal.
    pub const NEW_PROPOSAL: EventType =
        namada_events::event_type!(GovernanceEvent, PROPOSAL_SUBDOMAIN, "new");

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_gov_event_type_as_str() {
            assert_eq!(&*PROPOSAL_PASSED, "governance/proposal/passed");
        }
    }
}

/// Governance event.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum GovernanceEvent {
    /// Governance proposal event.
    Proposal {
        /// ID of the governance proposal.
        id: u64,
        /// Governance proposal kind.
        kind: ProposalEventKind,
    },
}

impl GovernanceEvent {
    /// Create a new proposal event for default proposal
    pub fn new_proposal(
        proposal_id: u64,
        proposal_type: GovProposalType,
    ) -> Self {
        Self::Proposal {
            id: proposal_id,
            kind: ProposalEventKind::NewProposal { proposal_type },
        }
    }

    /// Create a new proposal event for defaultwithwasm proposal
    pub fn passed_proposal(
        proposal_id: u64,
        has_proposal_code: bool,
        is_proposal_code_successful: bool,
    ) -> Self {
        Self::Proposal {
            id: proposal_id,
            kind: ProposalEventKind::Passed {
                has_proposal_code,
                is_proposal_code_successful,
            },
        }
    }

    pub fn rejected_proposal(
        proposal_id: u64,
        has_proposal_code: bool,
    ) -> Self {
        Self::Proposal {
            id: proposal_id,
            kind: ProposalEventKind::Rejected { has_proposal_code },
        }
    }
}

/// Proposal event kinds
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ProposalEventKind {
    /// New proposal event
    NewProposal { proposal_type: GovProposalType },
    /// Passed proposal
    Passed {
        has_proposal_code: bool,
        is_proposal_code_successful: bool,
    },
    /// Rejected proposal
    Rejected { has_proposal_code: bool },
}

impl From<GovernanceEvent> for Event {
    fn from(proposal_event: GovernanceEvent) -> Self {
        let GovernanceEvent::Proposal {
            id: proposal_id,
            kind,
        } = proposal_event;

        let (event_type, attributes) = match kind {
            ProposalEventKind::NewProposal { proposal_type } => {
                let event_type = types::NEW_PROPOSAL;
                let attributes = new_governance_proposal_attributes(
                    proposal_id,
                    proposal_type,
                );
                (event_type, attributes)
            }
            ProposalEventKind::Passed {
                has_proposal_code,
                is_proposal_code_successful,
            } => {
                let event_type = types::PROPOSAL_PASSED;
                let attributes = ended_governance_proposal_attributes(
                    GovTallyResult::Passed,
                    proposal_id,
                    has_proposal_code,
                    is_proposal_code_successful,
                );
                (event_type, attributes)
            }
            ProposalEventKind::Rejected { has_proposal_code } => {
                let event_type = types::PROPOSAL_REJECTED;
                let attributes = ended_governance_proposal_attributes(
                    GovTallyResult::Rejected,
                    proposal_id,
                    has_proposal_code,
                    false,
                );
                (event_type, attributes)
            }
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
fn ended_governance_proposal_attributes(
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

/// Return the attributes of a governance proposal.
#[inline]
fn new_governance_proposal_attributes(
    id: u64,
    proposal_type: GovProposalType,
) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    attrs.with_attribute(ProposalId(id));
    attrs.with_attribute(ProposalType(proposal_type));
    attrs
}

impl EventToEmit for GovernanceEvent {
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

/// Extend an [`Event`] with tally result data.
pub struct ProposalType(pub GovProposalType);

impl EventAttributeEntry<'static> for ProposalType {
    type Value = GovProposalType;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "proposal_type";

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
