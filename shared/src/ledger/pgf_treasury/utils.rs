//! Pgf Counsil Trasury Event utils

use std::collections::HashMap;

use namada_core::types::address::Address;
use namada_core::types::token::Amount;

/// Pgf event definition
pub struct PgfCounsilTrasuryEvent {
    /// Pgf counsil treasury event type
    pub event_type: String,
    /// Pgf counsil treasury event attributes
    pub attributes: HashMap<String, String>,
}

impl PgfCounsilTrasuryEvent {
    /// Create a counsil treasury event
    pub fn new(member_address: &Address, amount: &Amount) -> Self {
        let attributes = HashMap::from([
            ("counsil member".to_string(), member_address.to_string()),
            ("funded amount".to_string(), amount.to_string()),
        ]);
        Self {
            event_type: "PgfCounsilTreasury".to_string(),
            attributes,
        }
    }
}
