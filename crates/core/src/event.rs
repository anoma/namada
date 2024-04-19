//! Ledger events

pub mod extend;

use std::fmt::{self, Display};
use std::ops::{Index, IndexMut};
use std::str::FromStr;

use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use thiserror::Error;

use crate::borsh::{BorshDeserialize, BorshSerialize};
use crate::collections::HashMap;
use crate::ethereum_structs::{BpTransferStatus, EthBridgeEvent};
use crate::ibc::IbcEvent;

/// Used in sub-systems that may emit events.
pub trait EmitEvents {
    /// Emit a single [event](Event).
    fn emit<E>(&mut self, event: E)
    where
        E: Into<Event>;

    /// Emit a batch of [events](Event).
    fn emit_many<B, E>(&mut self, event_batch: B)
    where
        B: IntoIterator<Item = E>,
        E: Into<Event>;
}

impl EmitEvents for Vec<Event> {
    #[inline]
    fn emit<E>(&mut self, event: E)
    where
        E: Into<Event>,
    {
        self.push(event.into());
    }

    /// Emit a batch of [events](Event).
    fn emit_many<B, E>(&mut self, event_batch: B)
    where
        B: IntoIterator<Item = E>,
        E: Into<Event>,
    {
        self.extend(event_batch.into_iter().map(Into::into));
    }
}

/// Indicates if an event is emitted do to
/// an individual Tx or the nature of a finalized block
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub enum EventLevel {
    /// Indicates an event is to do with a finalized block.
    Block,
    /// Indicates an event is to do with an individual transaction.
    Tx,
}

impl Display for EventLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                EventLevel::Block => "block",
                EventLevel::Tx => "tx",
            }
        )
    }
}

/// Custom events that can be queried from Tendermint
/// using a websocket client
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct Event {
    /// The type of event.
    pub event_type: EventType,
    /// The level of the event - whether it relates to a block or an individual
    /// transaction.
    pub level: EventLevel,
    /// Key-value attributes of the event.
    // FIXME: maybe could use a dict here so that I can use a single entry of
    // Event for a batch? How should I index the single tx in the batch? With a
    // u64 or the Hash of the modified header (single Commitments)? Since I
    // iterate on the commitments I should probably use those,
    // FIXME: it would be slightly better thoug to have the hash of the wrapper
    // at the hihg level and the hash of just the comitments at a lower one so
    // that I can use only the Commitments one, otherwise I'd have to mock the
    // hash of the header with a single commitment? Probably I need to do both
    // of them anyway FIXME: also, there are some info that don't need to
    // be nested in the second hashmap, how to handle this? FIXME: should I
    // use an event for every inner tx? We are currently not doing this and I'd
    // like to avoid it FIXME: how to handle protocol txs in this case?
    // FIXME: comet does not suport nested dictionaries, so I need an event fro
    // every tx of the bundle, but how do I handle events for atomic batches?
    // Say the first tx succeed but the second one fail and I have to dump
    // everything, what should I log? FIXME: I think I have two ways:
    //    - I produce one event for every tx of the batch but also one event
    //      for the batch itself with the final result or something?
    //    - I produce a single event fo the entire batch and I put everything
    //      together -> but this is a problem because I cannot distinguish
    //      betwee ntxs which might be needed for some cases (e.g. masp client)
    // FIXME: let's do second case
    // FIXME: but what should I use as a hash to distinguish between them? I
    // could use the hash of the wrapper + a discriminant? Or the raw hash of
    // the header containing only the specified Commitment. No better wrapper
    // hash + discriminant -> What should this discriminant be? The entire
    // commitments section is too long, I just want a string, so either the
    // index or the hash of the Comittments section. Probably better the hash
    // cause I'm not using the indexes anywhere else
    pub attributes: HashMap<String, String>,
}

impl Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: print attributes, too
        write!(f, "{} in {}", self.event_type, self.level)
    }
}

/// The two types of custom events we currently use
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub enum EventType {
    /// The inner transaction was applied during block finalization
    Applied,
    /// The IBC transaction was applied during block finalization
    // TODO: create type-safe wrapper for all ibc event kinds
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
            "applied" => Ok(EventType::Applied),
            "proposal" => Ok(EventType::Proposal),
            "pgf_payments" => Ok(EventType::PgfPayment),
            // <IBC>
            "update_client" => Ok(EventType::Ibc("update_client".to_string())),
            "send_packet" => Ok(EventType::Ibc("send_packet".to_string())),
            "write_acknowledgement" => {
                Ok(EventType::Ibc("write_acknowledgement".to_string()))
            }
            // </IBC>
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
    /// Create an applied tx event with empty attributes.
    pub fn applied_tx() -> Self {
        Self {
            event_type: EventType::Applied,
            level: EventLevel::Tx,
            attributes: HashMap::new(),
        }
    }

    /// Check if the events keys contains a given string
    pub fn contains_key(&self, key: &str) -> bool {
        self.attributes.contains_key(key)
    }

    /// Get the value corresponding to a given key, if it exists.
    /// Else return None.
    pub fn get(&self, key: &str) -> Option<&String> {
        self.attributes.get(key)
    }

    /// Extend this [`Event`] with additional data.
    #[inline]
    pub fn extend<DATA>(&mut self, data: DATA) -> &mut Self
    where
        DATA: extend::ExtendEvent,
    {
        data.extend_event(self);
        self
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
        let entry = self.attributes.entry(index.into()).or_default();
        &mut *entry
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
