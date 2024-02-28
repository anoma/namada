//! Ledger events

use std::collections::HashMap;
use std::fmt::{self, Display};
use std::ops::{Index, IndexMut};
use std::str::FromStr;

use thiserror::Error;

use crate::borsh::{BorshDeserialize, BorshSerialize};
use crate::ethereum_structs::{BpTransferStatus, EthBridgeEvent};
use crate::ibc::IbcEvent;

/// Used in sub-systems that may emit events.
pub trait EmitEvents {
    /// Emit an event
    fn emit(&mut self, value: Event);
}

impl EmitEvents for Vec<Event> {
    fn emit(&mut self, value: Event) {
        Vec::push(self, value)
    }
}

/// Indicates if an event is emitted do to
/// an individual Tx or the nature of a finalized block
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum EventLevel {
    /// Indicates an event is to do with a finalized block.
    Block,
    /// Indicates an event is to do with an individual transaction.
    Tx,
}

/// Custom events that can be queried from Tendermint
/// using a websocket client
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Event {
    /// The type of event.
    pub event_type: EventType,
    /// The level of the event - whether it relates to a block or an individual
    /// transaction.
    pub level: EventLevel,
    /// Key-value attributes of the event.
    pub attributes: HashMap<String, String>,
}

/// The two types of custom events we currently use
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum EventType {
    /// The transaction was accepted to be included in a block
    Accepted,
    /// The transaction was applied during block finalization
    Applied,
    /// The IBC transaction was applied during block finalization
    Ibc(String),
    /// The proposal that has been executed
    Proposal,
    /// The pgf payment
    PgfPayment,
    /// Ethereum Bridge event
    EthereumBridge,
}

impl Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventType::Accepted => write!(f, "accepted"),
            EventType::Applied => write!(f, "applied"),
            EventType::Ibc(t) => write!(f, "{}", t),
            EventType::Proposal => write!(f, "proposal"),
            EventType::PgfPayment => write!(f, "pgf_payment"),
            EventType::EthereumBridge => write!(f, "ethereum_bridge"),
        }?;
        Ok(())
    }
}

impl FromStr for EventType {
    type Err = EventError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "accepted" => Ok(EventType::Accepted),
            "applied" => Ok(EventType::Applied),
            "proposal" => Ok(EventType::Proposal),
            "pgf_payments" => Ok(EventType::PgfPayment),
            // IBC
            "update_client" => Ok(EventType::Ibc("update_client".to_string())),
            "send_packet" => Ok(EventType::Ibc("send_packet".to_string())),
            "write_acknowledgement" => {
                Ok(EventType::Ibc("write_acknowledgement".to_string()))
            }
            "ethereum_bridge" => Ok(EventType::EthereumBridge),
            _ => Err(EventError::InvalidEventType),
        }
    }
}

/// Errors to do with emitting events.
#[derive(Error, Debug, Clone)]
pub enum EventError {
    /// Error when parsing an event type
    #[error("Invalid event type")]
    InvalidEventType,
    /// Error when parsing attributes from an event JSON.
    #[error("Json missing `attributes` field")]
    MissingAttributes,
    /// Missing key in attributes.
    #[error("Attributes missing key: {0}")]
    MissingKey(String),
    /// Missing value in attributes.
    #[error("Attributes missing value: {0}")]
    MissingValue(String),
}

impl Event {
    /// Check if the events keys contains a given string
    pub fn contains_key(&self, key: &str) -> bool {
        self.attributes.contains_key(key)
    }

    /// Get the value corresponding to a given key, if it exists.
    /// Else return None.
    pub fn get(&self, key: &str) -> Option<&String> {
        self.attributes.get(key)
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
            EthBridgeEvent::BridgePool { tx_hash, status } => Event {
                event_type: EventType::EthereumBridge,
                level: EventLevel::Tx,
                attributes: {
                    let mut attrs = HashMap::new();
                    attrs.insert(
                        "kind".into(),
                        match status {
                            BpTransferStatus::Relayed => "bridge_pool_relayed",
                            BpTransferStatus::Expired => "bridge_pool_expired",
                        }
                        .into(),
                    );
                    attrs.insert("tx_hash".into(), tx_hash.to_string());
                    attrs
                },
            },
        }
    }
}

impl Index<&str> for Event {
    type Output = String;

    fn index(&self, index: &str) -> &Self::Output {
        &self.attributes[index]
    }
}

impl IndexMut<&str> for Event {
    fn index_mut(&mut self, index: &str) -> &mut Self::Output {
        if !self.attributes.contains_key(index) {
            self.attributes.insert(String::from(index), String::new());
        }
        self.attributes.get_mut(index).unwrap()
    }
}

impl From<IbcEvent> for Event {
    fn from(ibc_event: IbcEvent) -> Self {
        Self {
            event_type: EventType::Ibc(ibc_event.event_type),
            level: EventLevel::Tx,
            attributes: ibc_event.attributes,
        }
    }
}

/// Convert our custom event into the necessary tendermint proto type
impl From<Event> for crate::tendermint_proto::v0_37::abci::Event {
    fn from(event: Event) -> Self {
        Self {
            r#type: event.event_type.to_string(),
            attributes: event
                .attributes
                .into_iter()
                .map(|(key, value)| {
                    crate::tendermint_proto::v0_37::abci::EventAttribute {
                        key,
                        value,
                        index: true,
                    }
                })
                .collect(),
        }
    }
}
