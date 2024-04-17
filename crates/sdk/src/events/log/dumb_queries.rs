//! Silly simple event matcher.

use namada_core::collections::HashMap;
use namada_core::hash::Hash;
use namada_core::keccak::KeccakHash;
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
    /// Returns the event type that this [`QueryMatcher`]
    /// attempts to match.
    pub fn event_type(&self) -> &EventType {
        &self.event_type
    }

    /// Checks if this [`QueryMatcher`] validates the
    /// given [`Event`].
    pub fn matches(&self, event: &Event) -> bool {
        if *event.kind() != self.event_type {
            return false;
        }
        event.has_subset_of_attrs(&self.attributes)
    }

    /// Returns a query matching the given relayed Bridge pool transaction hash.
    pub fn bridge_pool_relayed(tx_hash: &KeccakHash) -> Self {
        let mut attributes = HashMap::new();
        attributes.with_attribute(
            namada_core::ethereum_structs::BridgePoolTxHash(tx_hash),
        );
        Self {
            event_type:
                namada_core::ethereum_structs::event_types::BRIDGE_POOL_RELAYED,
            attributes,
        }
    }

    /// Returns a query matching the given expired Bridge pool transaction hash.
    pub fn bridge_pool_expired(tx_hash: &KeccakHash) -> Self {
        let mut attributes = HashMap::new();
        attributes.with_attribute(
            namada_core::ethereum_structs::BridgePoolTxHash(tx_hash),
        );
        Self {
            event_type:
                namada_core::ethereum_structs::event_types::BRIDGE_POOL_EXPIRED,
            attributes,
        }
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
    use crate::events::extend::ComposeEvent;
    use crate::events::EventLevel;

    /// Test if query matching is working as expected.
    #[test]
    fn test_tm_query_matching() {
        const HASH: &str =
            "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";

        let tx_hash: Hash = HASH.parse().unwrap();

        let matcher = QueryMatcher {
            event_type: APPLIED_TX,
            attributes: {
                let mut attrs = namada_core::collections::HashMap::new();
                attrs.with_attribute(TxHashAttr(tx_hash));
                attrs
            },
        };

        let tests = {
            let event_1: Event = Event::new(UPDATE_CLIENT, EventLevel::Block)
                .with(TxHashAttr(tx_hash))
                .into();
            let applied_1 = false;

            let event_2: Event = Event::new(APPLIED_TX, EventLevel::Tx)
                .with(TxHashAttr(tx_hash))
                .into();
            let applied_2 = true;

            [(event_1, applied_1), (event_2, applied_2)]
        };

        for (ref ev, status) in tests {
            if matcher.matches(ev) != status {
                panic!("Test failed");
            }
        }
    }
}
