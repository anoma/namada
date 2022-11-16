//! Silly simple Tendermint query parser.
//!
//! This parser will only work with simple queries of the form:
//!
//! ```text
//! tm.event='NewBlock' AND <accepted|applied>.<$attr>='<$value>'
//! ```

use crate::ledger::events::{Event, EventType};
use crate::types::hash::Hash;

/// A [`QueryMatcher`] verifies if a Namada event matches a
/// given Tendermint query.
#[derive(Debug, Clone)]
pub struct QueryMatcher {
    event_type: EventType,
    attr: String,
    value: Hash,
}

impl QueryMatcher {
    /// Checks if this [`QueryMatcher`] validates the
    /// given [`Event`].
    pub fn matches(&self, event: &Event) -> bool {
        event.event_type == self.event_type
            && event
                .attributes
                .get(&self.attr)
                .and_then(|value| {
                    value
                        .as_str()
                        .try_into()
                        .map(|v: Hash| v == self.value)
                        .ok()
                })
                .unwrap_or_default()
    }

    /// Returns a query matching the given accepted transaction hash.
    pub fn accepted(tx_hash: Hash) -> Self {
        Self {
            event_type: EventType::Accepted,
            attr: "hash".to_string(),
            value: tx_hash,
        }
    }

    /// Returns a query matching the given applied transaction hash.
    pub fn applied(tx_hash: Hash) -> Self {
        Self {
            event_type: EventType::Applied,
            attr: "hash".to_string(),
            value: tx_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::events::EventLevel;

    /// Test if query matching is working as expected.
    #[test]
    fn test_tm_query_matching() {
        const HASH: &str =
            "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";

        let matcher = QueryMatcher {
            event_type: EventType::Accepted,
            attr: "hash".to_string(),
            value: HASH.try_into().unwrap(),
        };

        let tests = {
            let event_1 = Event {
                event_type: EventType::Accepted,
                level: EventLevel::Block,
                attributes: {
                    let mut attrs = std::collections::HashMap::new();
                    attrs.insert("hash".to_string(), HASH.to_string());
                    attrs
                },
            };
            let accepted_1 = true;

            let event_2 = Event {
                event_type: EventType::Applied,
                level: EventLevel::Block,
                attributes: {
                    let mut attrs = std::collections::HashMap::new();
                    attrs.insert("hash".to_string(), HASH.to_string());
                    attrs
                },
            };
            let accepted_2 = false;

            [(event_1, accepted_1), (event_2, accepted_2)]
        };

        for (ref ev, status) in tests {
            if matcher.matches(ev) != status {
                panic!("Test failed");
            }
        }
    }
}
