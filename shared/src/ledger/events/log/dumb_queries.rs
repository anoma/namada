//! Silly simple Tendermint query parser.
//!
//! This parser will only work with simple queries of the form:
//!
//! ```text
//! tm.event='NewBlock' AND <accepted|applied>.<$attr>='<$value>'
//! ```

use std::collections::HashMap;

use crate::ibc::core::ics04_channel::packet::Sequence;
use crate::ibc::core::ics24_host::identifier::{ChannelId, ClientId, PortId};
use crate::ledger::events::{Event, EventType};
use crate::types::hash::Hash;
use crate::types::storage::BlockHeight;

/// A [`QueryMatcher`] verifies if a Namada event matches a
/// given Tendermint query.
#[derive(Debug, Clone)]
pub struct QueryMatcher {
    event_type: EventType,
    attributes: HashMap<String, String>,
}

impl QueryMatcher {
    /// Checks if this [`QueryMatcher`] validates the
    /// given [`Event`].
    pub fn matches(&self, event: &Event) -> bool {
        if event.event_type != self.event_type {
            return false;
        }

        for attr in &self.attributes {
            if let Some(value) = event.attributes.get(attr.0) {
                if value != attr.1 {
                    return false;
                }
            }
        }

        true
    }

    /// Returns a query matching the given accepted transaction hash.
    pub fn accepted(tx_hash: Hash) -> Self {
        let mut attributes = HashMap::new();
        attributes.insert("hash".to_string(), tx_hash.to_string());
        Self {
            event_type: EventType::Accepted,
            attributes,
        }
    }

    /// Returns a query matching the given applied transaction hash.
    pub fn applied(tx_hash: Hash) -> Self {
        let mut attributes = HashMap::new();
        attributes.insert("hash".to_string(), tx_hash.to_string());
        Self {
            event_type: EventType::Applied,
            attributes,
        }
    }

    /// Returns a query matching the given IBC UpdateClient parameters
    pub fn ibc_update_client(
        client_id: ClientId,
        consensus_height: BlockHeight,
    ) -> Self {
        let mut attributes = HashMap::new();
        attributes.insert("client_id".to_string(), client_id.to_string());
        attributes.insert(
            "consensus_height".to_string(),
            format!("0-{}", consensus_height),
        );
        Self {
            event_type: EventType::Ibc("update_client".to_string()),
            attributes,
        }
    }

    /// Returns a query matching the given IBC packet parameters
    pub fn ibc_packet(
        event_type: EventType,
        source_port: PortId,
        source_channel: ChannelId,
        destination_port: PortId,
        destination_channel: ChannelId,
        sequence: Sequence,
    ) -> Self {
        let mut attributes = HashMap::new();
        attributes.insert("src_port".to_string(), source_port.to_string());
        attributes
            .insert("src_channel".to_string(), source_channel.to_string());
        attributes.insert("dst_port".to_string(), destination_port.to_string());
        attributes
            .insert("dst_channel".to_string(), destination_channel.to_string());
        attributes.insert("sequence".to_string(), sequence.to_string());
        Self {
            event_type,
            attributes,
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

        let mut attributes = HashMap::new();
        attributes.insert("hash".to_string(), HASH.to_string());
        let matcher = QueryMatcher {
            event_type: EventType::Accepted,
            attributes,
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
