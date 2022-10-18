//! Silly simple Tendermint query parser.
//!
//! This parser will only work with simple queries of the form:
//!
//! ```text
//! tm.event='NewBlock' AND <accepted|applied>.<$attr>='<$value>'
//! ```

use std::marker::PhantomData;
use namada::types::hash::Hash;

use crate::node::ledger::events::{Event, EventType};

/// A [`QueryMatcher`] verifies if a Namada event matches a
/// given Tendermint query.
#[derive(Debug, Clone)]
pub struct QueryMatcher<'a, T>
{
    event_type: EventType,
    attr: String,
    value: T,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> QueryMatcher<'a, T>
where
    T: 'a + PartialEq + TryFrom<&'a str>
{
    /// Checks if this [`QueryMatcher`] validates the
    /// given [`Event`].
    pub fn matches(&self, event: &'a Event) -> bool {
        event.event_type == self.event_type
            && event
            .attributes
            .get(&self.attr)
            .map(|value| T::try_from(value.as_ref()).map(|v| v == self.value).unwrap_or(false))
            .unwrap_or_default()
    }
}

impl QueryMatcher<'_, Hash> {

    /// Returns a query matching the given accepted transaction hash.
    pub fn accepted(tx_hash: Hash) -> Self {
        Self {
            event_type: EventType::Accepted,
            attr: "hash".to_string(),
            value: tx_hash,
            phantom: PhantomData,
        }
    }

    /// Returns a query matching the given applied transaction hash.
    pub fn applied(tx_hash: Hash) -> Self {
        Self {
            event_type: EventType::Applied,
            attr: "hash".to_string(),
            value: tx_hash,
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::ledger::events::EventLevel;

    /// Test if query matching is working as expected.
    #[test]
    fn test_tm_query_matching() {
        let matcher = QueryMatcher {
            event_type: EventType::Accepted,
            attr: "hash".to_string(),
            value: "DEADBEEF",
            phantom: PhantomData,
        };

        let tests = {
            let event_1 = Event {
                event_type: EventType::Accepted,
                level: EventLevel::Block,
                attributes: {
                    let mut attrs = std::collections::HashMap::new();
                    attrs.insert("hash".to_string(), "DEADBEEF".to_string());
                    attrs
                },
            };
            let accepted_1 = true;

            let event_2 = Event {
                event_type: EventType::Applied,
                level: EventLevel::Block,
                attributes: {
                    let mut attrs = std::collections::HashMap::new();
                    attrs.insert("hash".to_string(), "DEADBEEF".to_string());
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
