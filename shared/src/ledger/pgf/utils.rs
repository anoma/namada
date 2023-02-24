//! Pgf utils

use std::collections::HashMap;

use namada_core::types::address::Address;
use namada_core::types::token::Amount;

/// Pgf event definition
pub struct PgfEvent {
    /// Proposal event type
    pub event_type: String,
    /// Proposal event attributes
    pub attributes: HashMap<String, String>,
}

impl PgfEvent {
    /// Create a proposal event
    pub fn new(project_address: &Address, project_amount: &Amount) -> Self {
        let attributes = HashMap::from([
            ("project".to_string(), project_address.to_string()),
            ("funded amount".to_string(), project_amount.to_string()),
        ]);
        Self {
            event_type: "Pgf".to_string(),
            attributes,
        }
    }
}
