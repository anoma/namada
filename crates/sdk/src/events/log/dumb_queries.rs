//! Silly simple Tendermint query parser
//!
//! This parser will only work with simple queries of the form:
//!
//! ```text
//! tm.event='NewBlock' AND <accepted|applied>.<$attr>='<$value>'
//! ```

use namada_core::collections::HashMap;
use namada_core::hash::Hash;
use namada_core::storage::BlockHeight;

use crate::events::extend::{ExtendAttributesMap, TxHash as TxHashAttr};
use crate::events::{Event, EventType};
use crate::ibc::core::client::types::Height as IbcHeight;
use crate::ibc::core::host::types::identifiers::{
    ChannelId, ClientId, PortId, Sequence,
};
use crate::ibc::event::types::UPDATE_CLIENT;
use crate::ibc::event::{
    ClientId as ClientIdAttr, ConsensusHeights, PacketDstChannel,
    PacketDstPort, PacketSequence, PacketSrcChannel, PacketSrcPort,
};
use crate::tx::event::types::APPLIED as APPLIED_TX;

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

        self.attributes.iter().all(|(key, value)| {
            match event.attributes.get(key) {
                Some(v) => v == value,
                None => false,
            }
        })
    }

    /// Returns a query matching the given applied transaction hash.
    pub fn applied(tx_hash: Hash) -> Self {
        let mut attributes = HashMap::new();
        attributes.with_attribute(TxHashAttr(tx_hash));
        Self {
            event_type: APPLIED_TX,
            attributes,
        }
    }

    /// Returns a query matching the given IBC UpdateClient parameters
    pub fn ibc_update_client(
        client_id: ClientId,
        consensus_height: BlockHeight,
    ) -> Self {
        let mut attributes = HashMap::new();

        attributes
            .with_attribute(ClientIdAttr(client_id))
            .with_attribute(ConsensusHeights(
                IbcHeight::new(0, consensus_height.0).expect("invalid height"),
            ));

        Self {
            event_type: UPDATE_CLIENT,
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

        attributes
            .with_attribute(PacketSrcPort(source_port))
            .with_attribute(PacketSrcChannel(source_channel))
            .with_attribute(PacketDstPort(destination_port))
            .with_attribute(PacketDstChannel(destination_channel))
            .with_attribute(PacketSequence(sequence));

        Self {
            event_type,
            attributes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventLevel;
    use crate::tx::event::types::ACCEPTED as ACCEPTED_TX;

    /// Test if query matching is working as expected.
    #[test]
    fn test_tm_query_matching() {
        const HASH: &str =
            "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";

        let tx_hash: Hash = HASH.parse().unwrap();

        let mut attributes = HashMap::new();
        attributes.with_attribute(TxHashAttr(tx_hash));
        let matcher = QueryMatcher {
            event_type: ACCEPTED_TX,
            attributes,
        };

        let tests = {
            let event_1 = Event {
                event_type: ACCEPTED_TX,
                level: EventLevel::Block,
                attributes: {
                    let mut attrs = namada_core::collections::HashMap::new();
                    attrs.with_attribute(TxHashAttr(tx_hash));
                    attrs
                },
            };
            let accepted_1 = true;

            let event_2 = Event {
                event_type: APPLIED_TX,
                level: EventLevel::Block,
                attributes: {
                    let mut attrs = namada_core::collections::HashMap::new();
                    attrs.with_attribute(TxHashAttr(tx_hash));
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
