//! Ethereum Bridge transaction events.

use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::keccak::KeccakHash;
use namada_events::extend::{ComposeEvent, EventAttributeEntry};
use namada_events::{Event, EventError, EventLevel, EventToEmit, EventType};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

pub mod types {
    //! Ethereum bridge event types.

    use namada_events::{EventType, event_type};

    use super::EthBridgeEvent;

    /// Bridge pool relay event.
    pub const BRIDGE_POOL_RELAYED: EventType =
        event_type!(EthBridgeEvent, "bridge-pool", "relayed");

    /// Bridge pool expiration event.
    pub const BRIDGE_POOL_EXPIRED: EventType =
        event_type!(EthBridgeEvent, "bridge-pool", "expired");
}

/// Status of some Bridge pool transfer.
#[derive(
    Hash,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub enum BpTransferStatus {
    /// The transfer has been relayed.
    Relayed,
    /// The transfer has expired.
    Expired,
}

impl From<BpTransferStatus> for EventType {
    fn from(transfer_status: BpTransferStatus) -> Self {
        (&transfer_status).into()
    }
}

impl From<&BpTransferStatus> for EventType {
    fn from(transfer_status: &BpTransferStatus) -> Self {
        match transfer_status {
            BpTransferStatus::Relayed => types::BRIDGE_POOL_RELAYED,
            BpTransferStatus::Expired => types::BRIDGE_POOL_EXPIRED,
        }
    }
}

impl TryFrom<EventType> for BpTransferStatus {
    type Error = EventError;

    fn try_from(event_type: EventType) -> Result<Self, Self::Error> {
        (&event_type).try_into()
    }
}

impl TryFrom<&EventType> for BpTransferStatus {
    type Error = EventError;

    fn try_from(event_type: &EventType) -> Result<Self, Self::Error> {
        if *event_type == types::BRIDGE_POOL_RELAYED {
            Ok(BpTransferStatus::Relayed)
        } else if *event_type == types::BRIDGE_POOL_EXPIRED {
            Ok(BpTransferStatus::Expired)
        } else {
            Err(EventError::InvalidEventType)
        }
    }
}

/// Ethereum bridge events on Namada's event log.
#[derive(
    Hash,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub enum EthBridgeEvent {
    /// Bridge pool transfer status update event.
    BridgePool {
        /// Hash of the Bridge pool transfer.
        tx_hash: KeccakHash,
        /// Status of the Bridge pool transfer.
        status: BpTransferStatus,
    },
}

impl EthBridgeEvent {
    /// Return a new Bridge pool expired transfer event.
    pub const fn new_bridge_pool_expired(tx_hash: KeccakHash) -> Self {
        Self::BridgePool {
            tx_hash,
            status: BpTransferStatus::Expired,
        }
    }

    /// Return a new Bridge pool relayed transfer event.
    pub const fn new_bridge_pool_relayed(tx_hash: KeccakHash) -> Self {
        Self::BridgePool {
            tx_hash,
            status: BpTransferStatus::Relayed,
        }
    }
}

impl From<EthBridgeEvent> for Event {
    #[inline]
    fn from(event: EthBridgeEvent) -> Event {
        Self::from(&event)
    }
}

impl From<&EthBridgeEvent> for Event {
    fn from(event: &EthBridgeEvent) -> Event {
        match event {
            EthBridgeEvent::BridgePool { tx_hash, status } => {
                Event::new(status.into(), EventLevel::Tx)
                    .with(BridgePoolTxHash(tx_hash))
                    .into()
            }
        }
    }
}

impl EventToEmit for EthBridgeEvent {
    const DOMAIN: &'static str = "eth-bridge";
}

/// Hash of bridge pool transaction
pub struct BridgePoolTxHash<'tx>(pub &'tx KeccakHash);

impl<'tx> EventAttributeEntry<'tx> for BridgePoolTxHash<'tx> {
    type Value = &'tx KeccakHash;
    type ValueOwned = KeccakHash;

    const KEY: &'static str = "bridge_pool_tx_hash";

    fn into_value(self) -> Self::Value {
        self.0
    }
}
