use std::collections::HashMap;

use namada_core::address::Address;

use crate::ledger::events::EventType;
use crate::token;

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
        target: Address,
        amount: token::Amount,
        is_steward: bool,
        success: bool,
    ) -> Self {
        let attributes = HashMap::from([
            ("target".to_string(), target.to_string()),
            ("amount".to_string(), amount.to_string_native()),
            ("is_steward".to_string(), is_steward.to_string()),
            ("successed".to_string(), success.to_string()),
        ]);
        Self {
            event_type,
            attributes,
        }
    }

    /// Create a new proposal event for pgf continuous funding
    pub fn pgf_funding_payment(
        target: Address,
        amount: token::Amount,
        success: bool,
    ) -> Self {
        ProposalEvent::new(
            EventType::PgfPayment.to_string(),
            target,
            amount,
            false,
            success,
        )
    }

    /// Create a new proposal event for steward payments
    pub fn pgf_steward_payment(
        target: Address,
        amount: token::Amount,
        success: bool,
    ) -> Self {
        ProposalEvent::new(
            EventType::PgfPayment.to_string(),
            target,
            amount,
            true,
            success,
        )
    }
}
