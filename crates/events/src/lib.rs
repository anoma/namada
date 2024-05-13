//! Events emitted by the Namada ledger.

pub mod extend;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::ops::Deref;
use std::str::FromStr;

use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[doc(hidden)]
#[macro_export]
macro_rules! __event_type_impl {
    ($domain:ty) => {
        <$domain as $crate::EventToEmit>::DOMAIN
    };
    ($domain:ty, $($subdomain:expr),*) => {
        ::konst::string::str_join!(
            "/",
            &[
                $crate::__event_type_impl!($domain),
                $($subdomain),*
            ],
        )
    };
}

/// Instantiate a new [`EventType`] in const contexts. Mostly
/// useful to define new event types in the protocol.
///
/// # Example
///
/// ```ignore
/// const RELAYED: EventType = event_type!(EthBridgeEvent, "bridge-pool", "relayed");
/// ```
#[macro_export]
macro_rules! event_type {
    ($($tt:tt)*) => {
        $crate::EventType::new($crate::__event_type_impl!($($tt)*))
    };
}

/// An event to be emitted in Namada.
pub trait EventToEmit: Into<Event> {
    /// The domain of the event to emit.
    ///
    /// This may be used to group events of a certain kind.
    const DOMAIN: &'static str;
}

impl EventToEmit for Event {
    const DOMAIN: &'static str = "unknown";
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
    Ord,
    PartialOrd,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
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
    Serialize,
    Deserialize,
)]
#[repr(transparent)]
pub struct EventType {
    inner: Cow<'static, str>,
}

impl Deref for EventType {
    type Target = str;

    #[inline(always)]
    fn deref(&self) -> &str {
        &self.inner
    }
}

impl EventType {
    /// Create a new event type.
    pub const fn new(event_type: &'static str) -> Self {
        Self {
            inner: Cow::Borrowed(event_type),
        }
    }

    /// Retrieve the domain of some event.
    #[inline]
    pub fn domain(&self) -> &str {
        self.inner
            .split_once('/')
            .map(|(domain, _sub_domain)| domain)
            .unwrap_or("unknown")
    }

    /// Retrieve the sub-domain of some event.
    #[inline]
    pub fn sub_domain(&self) -> &str {
        self.inner
            .split_once('/')
            .map(|(_domain, sub_domain)| sub_domain)
            .unwrap_or("")
    }
}

impl Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl FromStr for EventType {
    type Err = EventError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.split_once('/').ok_or(EventError::MissingDomain)?;
        Ok(Self {
            inner: Cow::Owned(s.into()),
        })
    }
}

/// Build an [`EventType`] segment by segment.
pub struct EventTypeBuilder {
    inner: String,
}

impl EventTypeBuilder {
    /// Create a new [`EventTypeBuilder`] with the given type.
    #[inline]
    pub fn new_with_type(ty: impl Into<String>) -> Self {
        Self { inner: ty.into() }
    }

    /// Create a new [`EventTypeBuilder`] with the domain of the
    /// given event type.
    #[inline]
    pub fn new_of<E: EventToEmit>() -> Self {
        Self::new_with_type(E::DOMAIN)
    }

    /// Append a new segment to the final [`EventType`] and return
    /// a mutable reference to the builder.
    #[inline]
    pub fn append_segment(&mut self, segment: impl AsRef<str>) -> &mut Self {
        let segment = segment.as_ref();

        if !segment.is_empty() {
            self.inner.push('/');
            self.inner.push_str(segment.as_ref());
        }

        self
    }

    /// Append a new segment to the final [`EventType`] and return
    /// the builder.
    #[inline]
    pub fn with_segment(mut self, segment: impl AsRef<str>) -> Self {
        self.append_segment(segment);
        self
    }

    /// Build the final [`EventType`].
    #[inline]
    pub fn build(self) -> EventType {
        EventType {
            inner: Cow::Owned(self.inner),
        }
    }
}

/// Custom events that can be queried from Tendermint
/// using a websocket client
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
    Serialize,
    Deserialize,
)]
pub struct Event {
    /// The level of the event - whether it relates to a block or an individual
    /// transaction.
    level: EventLevel,
    /// The type of event.
    event_type: EventType,
    /// Key-value attributes of the event.
    attributes: BTreeMap<String, String>,
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
    /// Invalid event domain.
    #[error("Invalid event domain: {0}")]
    InvalidDomain(String),
    /// Missing event domain.
    #[error("Missing the domain of the event")]
    MissingDomain,
    /// Error resulting from a missing event attribute.
    #[error("Missing event attribute {0:?}")]
    MissingAttribute(&'static str),
    /// Error resulting from an invalid encoding of an event attribute.
    #[error("Failed to parse event attribute: {0}")]
    AttributeEncoding(String),
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
    /// Create a new event with no attributes and the given parameters.
    pub fn new(event_type: EventType, level: EventLevel) -> Self {
        Self {
            event_type,
            level,
            attributes: BTreeMap::new(),
        }
    }

    /// Return the level of the event.
    #[inline]
    pub fn level(&self) -> &EventLevel {
        &self.level
    }

    /// Return the type of the event.
    #[inline]
    pub fn kind(&self) -> &EventType {
        &self.event_type
    }

    /// Return a reference to the event's attributes.
    #[deprecated = "Accessing the event attributes directly is deprecated. \
                    Consider using domain types to compose events with \
                    attributes."]
    #[inline]
    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }

    /// Return a mutable reference to the event's attributes.
    #[deprecated = "Accessing the event attributes directly is deprecated. \
                    Consider using domain types to compose events with \
                    attributes."]
    #[inline]
    pub fn attributes_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.attributes
    }

    /// Return the attributes of the event, destroying
    /// it in the process.
    #[inline]
    pub fn into_attributes(self) -> BTreeMap<String, String> {
        self.attributes
    }

    /// Check if this [`Event`] has a subset of the keys and values
    /// in `attrs`.
    #[inline]
    pub fn has_subset_of_attrs<A: extend::AttributesMap>(
        &self,
        attrs: &A,
    ) -> bool {
        attrs.iter_attributes().all(|(key, value)| {
            match self.attributes.get(key) {
                Some(v) => v == value,
                None => false,
            }
        })
    }

    /// Get the raw string value corresponding to a given attribute, if it
    /// exists.
    #[inline]
    pub fn raw_read_attribute<'value, DATA>(&self) -> Option<&str>
    where
        DATA: extend::RawReadFromEventAttributes<'value>,
    {
        DATA::raw_read_opt_from_event_attributes(&self.attributes)
    }

    /// Get the value corresponding to a given attribute.
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

    /// Get the value corresponding to a given attribute, if it exists.
    #[inline]
    pub fn read_attribute_opt<'value, DATA>(
        &self,
    ) -> Result<
        Option<<DATA as extend::ReadFromEventAttributes<'value>>::Value>,
        EventError,
    >
    where
        DATA: extend::ReadFromEventAttributes<'value>,
    {
        DATA::read_opt_from_event_attributes(&self.attributes)
    }

    /// Check if a certain attribute is present in the event.
    #[inline]
    pub fn has_attribute<'value, DATA>(&self) -> bool
    where
        DATA: extend::RawReadFromEventAttributes<'value>,
    {
        DATA::check_if_present_in(&self.attributes)
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

    /// Compute the gas cost of emitting this event.
    #[inline]
    pub fn emission_gas_cost(&self, cost_per_byte: u64) -> u64 {
        let len = self
            .attributes
            .iter()
            .fold(0, |acc, (k, v)| acc + k.len() + v.len());
        len as u64 * cost_per_byte
    }
}

impl From<Event> for namada_core::tendermint_proto::v0_37::abci::Event {
    fn from(event: Event) -> Self {
        Self {
            r#type: {
                use extend::{Domain, RawReadFromEventAttributes};

                if Domain::<Event>::check_if_present_in(&event.attributes) {
                    // NB: encode the domain of the event in the attributes.
                    // this is necessary for ibc events, as hermes is not
                    // compatible with our event type format.
                    event.event_type.sub_domain().to_string()
                } else {
                    event.event_type.to_string()
                }
            },
            attributes: event
                .attributes
                .into_iter()
                .map(|(key, value)| {
                    namada_core::tendermint_proto::v0_37::abci::EventAttribute {
                        key,
                        value,
                        index: true,
                    }
                })
                .chain(std::iter::once_with(|| {
                    namada_core::tendermint_proto::v0_37::abci::EventAttribute {
                        key: "event-level".to_string(),
                        value: event.level.to_string(),
                        index: true,
                    }
                }))
                .collect(),
        }
    }
}

impl From<Event> for namada_core::tendermint::abci::Event {
    fn from(event: Event) -> Self {
        Self {
            kind: {
                use extend::{Domain, RawReadFromEventAttributes};

                if Domain::<Event>::check_if_present_in(&event.attributes) {
                    // NB: encode the domain of the event in the attributes.
                    // this is necessary for ibc events, as hermes is not
                    // compatible with our event type format.
                    event.event_type.sub_domain().to_string()
                } else {
                    event.event_type.to_string()
                }
            },
            attributes: event
                .attributes
                .into_iter()
                .map(|(key, value)| (key, value, true).into())
                .chain(std::iter::once_with(|| {
                    ("event-level", event.level.to_string(), true).into()
                }))
                .collect(),
        }
    }
}
