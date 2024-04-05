//! Ledger events

pub mod extend;

use std::borrow::Cow;
use std::fmt::{self, Display};
use std::ops::Deref;
use std::str::FromStr;

use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use thiserror::Error;

use crate::borsh::{BorshDeserialize, BorshSerialize};
use crate::collections::HashMap;
use crate::ethereum_structs::EthBridgeEvent;
use crate::ibc::IbcEvent;

// TODO: remove this
macro_rules! event_type {
    ($domain:expr, $($subdomain:expr),*) => {
        EventType {
            domain: EventSegment::new($domain),
            sub_domain: Cow::Owned(vec![$(EventSegment::new($subdomain)),*]),
        }
    };
    ($domain:expr) => {
        event_type!($domain,)
    };
}

/// An event to be emitted in Namada.
pub trait EventToEmit: Into<Event> {
    /// The domain of the event to emit.
    ///
    /// This may be used to group events of a certain kind.
    const DOMAIN: EventSegment;
}

/// Create a new constant event type.
pub const fn new_event_type_of<E>(
    sub_domain: Cow<'static, [EventSegment]>,
) -> EventType
where
    E: EventToEmit,
{
    EventType {
        domain: E::DOMAIN,
        sub_domain,
    }
}

impl EventToEmit for Event {
    const DOMAIN: EventSegment = EventSegment::new_static("unknown");
}

impl EventToEmit for IbcEvent {
    const DOMAIN: EventSegment = EventSegment::new_static("ibc");
}

impl EventToEmit for EthBridgeEvent {
    const DOMAIN: EventSegment = EventSegment::new_static("eth-bridge");
}

/// Used in sub-systems that may emit events.
pub trait EmitEvents {
    /// Emit a single [event](Event).
    fn emit<E>(&mut self, event: E)
    where
        E: EventToEmit;

    /// Emit a batch of [events](Event).
    fn emit_many<B, E>(&mut self, event_batch: B)
    where
        B: IntoIterator<Item = E>,
        E: EventToEmit;
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
    Hash,
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

/// Logical segmentation of an ABCI event kind.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
#[repr(transparent)]
pub struct EventSegment {
    inner: Cow<'static, str>,
}

impl EventSegment {
    /// Instantiate a new [`EventSegment`].
    #[inline]
    pub fn new<S>(segment: S) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        Self {
            inner: segment.into(),
        }
    }

    /// Instantiate a new [`EventSegment`] from a static string.
    pub const fn new_static(domain: &'static str) -> Self {
        Self {
            inner: Cow::Borrowed(domain),
        }
    }
}

impl Deref for EventSegment {
    type Target = str;

    #[inline(always)]
    fn deref(&self) -> &str {
        &self.inner
    }
}

impl Display for EventSegment {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// ABCI event type.
///
/// It is comprised of an event domain and sub-domain, plus any other
/// specifiers.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct EventType {
    /// The domain of an [`Event`]. Usually, this is equivalent to the
    /// protocol subsystem the event originated from (e.g. IBC, Ethereum
    /// Bridge).
    pub domain: EventSegment,
    /// Further describes the event with a sub-domain.
    pub sub_domain: Cow<'static, [EventSegment]>,
}

impl EventType {
    /// Retrieve the sub-domain of some event.
    pub fn sub_domain(&self) -> String {
        let mut output = String::new();
        let mut segments = self.sub_domain.iter();

        if let Some(segment) = segments.next() {
            output.push_str(segment);
        } else {
            return output;
        }

        for segment in segments {
            output.push('/');
            output.push_str(segment);
        }

        output
    }
}

impl Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { domain, sub_domain } = self;
        write!(f, "{domain}")?;
        for segment in sub_domain.iter() {
            write!(f, "/{segment}")?;
        }
        Ok(())
    }
}

impl FromStr for EventType {
    type Err = EventError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut segments = s.split('/');

        let domain = segments
            .next()
            .map(String::from)
            .map(EventSegment::new)
            .ok_or(EventError::MissingDomain)?;
        let sub_domain = segments
            .map(String::from)
            .map(EventSegment::new)
            .collect::<Vec<_>>()
            .into();

        Ok(Self { domain, sub_domain })
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
    /// The level of the event - whether it relates to a block or an individual
    /// transaction.
    pub level: EventLevel,
    /// The type of event.
    pub event_type: EventType,
    /// Key-value attributes of the event.
    pub attributes: HashMap<String, String>,
}

impl Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: print attributes, too
        write!(f, "{} in {}", self.event_type, self.level)
    }
}

/// Errors to do with emitting events.
#[derive(Error, Debug, Clone)]
pub enum EventError {
    /// Missing event domain.
    #[error("Missing the domain of the event")]
    MissingDomain,
    /// Failed to retrieve an event attribute.
    #[error("Failed to retrieve event attribute: {0}")]
    AttributeRetrieval(String),
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
            event_type: event_type!("tx", "applied"),
            level: EventLevel::Tx,
            attributes: HashMap::new(),
        }
    }

    /// Get the value corresponding to a given attribute, if it exists.
    #[inline]
    pub fn read_attribute<'value, DATA>(
        &self,
    ) -> Result<
        <DATA as extend::ReadFromEventAttributes<'value>>::Value,
        EventError,
    >
    where
        DATA: extend::ReadFromEventAttributes<'value>,
    {
        DATA::read_from_event_attributes(&self.attributes)
    }

    /// Check if a certain attribute is present in the event.
    #[inline]
    pub fn has_attribute<'value, DATA>(&self) -> bool
    where
        DATA: extend::RawReadFromEventAttributes<'value>,
    {
        DATA::check_if_attribute_present(&self.attributes)
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
                event_type: status.into(),
                level: EventLevel::Tx,
                attributes: {
                    use self::extend::ExtendAttributesMap;
                    use crate::ethereum_structs::BridgePoolTxHash;

                    let mut attributes = HashMap::new();
                    attributes.with_attribute(BridgePoolTxHash(tx_hash));
                    attributes
                },
            },
        }
    }
}

impl From<IbcEvent> for Event {
    fn from(ibc_event: IbcEvent) -> Self {
        Self {
            event_type: event_type!("ibc", ibc_event.event_type),
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
                .chain(std::iter::once_with(|| {
                    crate::tendermint_proto::v0_37::abci::EventAttribute {
                        key: "event-level".to_string(),
                        value: event.level.to_string(),
                        index: true,
                    }
                }))
                .collect(),
        }
    }
}
