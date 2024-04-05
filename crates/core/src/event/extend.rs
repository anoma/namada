//! Extend [events](Event) with additional fields.

use std::fmt::Display;
use std::str::FromStr;

use super::*;
use crate::hash::Hash;
use crate::storage::BlockHeight;

/// Map of event attributes.
pub trait AttributesMap {
    /// Insert a new attribute.
    fn insert_attribute<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: Into<String>;

    /// Retrieve an attribute.
    fn retrieve_attribute(&self, key: &str) -> Option<&str>;

    /// Check for the existence of an attribute.
    fn is_attribute(&self, key: &str) -> bool;
}

impl AttributesMap for HashMap<String, String> {
    #[inline]
    fn insert_attribute<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.insert(key.into(), value.into());
    }

    #[inline]
    fn retrieve_attribute(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_ref)
    }

    #[inline]
    fn is_attribute(&self, key: &str) -> bool {
        self.contains_key(key)
    }
}

/// Provides event composition routines.
pub trait ComposeEvent {
    /// Compose an [event](Event) with new data.
    fn with<NEW>(self, data: NEW) -> CompositeEvent<NEW, Self>
    where
        Self: Sized;
}

impl<E> ComposeEvent for E
where
    E: Into<Event>,
{
    #[inline(always)]
    fn with<NEW>(self, data: NEW) -> CompositeEvent<NEW, E> {
        CompositeEvent::new(self, data)
    }
}

/// Event composed of various other event extensions.
#[derive(Clone, Debug)]
pub struct CompositeEvent<DATA, E> {
    base_event: E,
    data: DATA,
}

impl<E, DATA> CompositeEvent<DATA, E> {
    /// Create a new composed event.
    pub const fn new(base_event: E, data: DATA) -> Self {
        Self { base_event, data }
    }
}

impl<E, DATA> From<CompositeEvent<DATA, E>> for Event
where
    E: Into<Event>,
    DATA: ExtendEvent,
{
    #[inline]
    fn from(composite: CompositeEvent<DATA, E>) -> Event {
        let CompositeEvent { base_event, data } = composite;

        let mut base_event = base_event.into();
        data.extend_event(&mut base_event);

        base_event
    }
}

impl<E, DATA> EventToEmit for CompositeEvent<DATA, E>
where
    E: EventToEmit,
    DATA: ExtendEvent,
{
    const DOMAIN: EventSegment = E::DOMAIN;
}

/// Extend a [`HashMap`] of string to string with event attributed
/// related methods.
pub trait ExtendAttributesMap: Sized {
    /// Insert a new attribute into a map of event attributes.
    fn with_attribute<DATA>(&mut self, data: DATA) -> &mut Self
    where
        DATA: ExtendEventAttributes;
}

impl<A: AttributesMap> ExtendAttributesMap for A {
    #[inline(always)]
    fn with_attribute<DATA>(&mut self, data: DATA) -> &mut Self
    where
        DATA: ExtendEventAttributes,
    {
        data.extend_event_attributes(self);
        self
    }
}

/// Represents an entry in the attributes of an [`Event`].
pub trait EventAttributeEntry<'a> {
    /// Key to read or write and event attribute to.
    const KEY: &'static str;

    /// Data to be stored in the given `KEY`.
    type Value;

    /// Identical to [`Self::Value`], with the exception that this
    /// should be an owned variant of that type.
    type ValueOwned;

    /// Return the data to be stored in the given `KEY`.
    fn into_value(self) -> Self::Value;
}

/// Extend an [event](Event) with additional attributes.
pub trait ExtendEventAttributes {
    /// Add additional attributes to some `event`.
    fn extend_event_attributes<A>(self, attributes: &mut A)
    where
        A: AttributesMap;
}

impl<'value, DATA> ExtendEventAttributes for DATA
where
    DATA: EventAttributeEntry<'value>,
    DATA::Value: ToString,
{
    #[inline]
    fn extend_event_attributes<A>(self, attributes: &mut A)
    where
        A: AttributesMap,
    {
        attributes.insert_attribute(
            DATA::KEY.to_string(),
            self.into_value().to_string(),
        );
    }
}

/// Read an attribute from an [event](Event)'s attributes.
pub trait ReadFromEventAttributes<'value>: Sized {
    /// The attribute to be read.
    type Value;

    /// Read an attribute from the provided event attributes.
    fn read_from_event_attributes<A>(
        attributes: &A,
    ) -> Result<Self::Value, EventError>
    where
        A: AttributesMap;
}

// NB: some domain specific types take references instead of owned
// values as arguments, so we must decode into the owned counterparts
// of these types... hence the trait spaghetti
impl<'value, DATA> ReadFromEventAttributes<'value> for DATA
where
    DATA: EventAttributeEntry<'value>,
    <DATA as EventAttributeEntry<'value>>::ValueOwned: FromStr,
    <<DATA as EventAttributeEntry<'value>>::ValueOwned as FromStr>::Err:
        Display,
{
    type Value = <DATA as EventAttributeEntry<'value>>::ValueOwned;

    #[inline]
    fn read_from_event_attributes<A>(
        attributes: &A,
    ) -> Result<Self::Value, EventError>
    where
        A: AttributesMap,
    {
        let encoded_value =
            attributes.retrieve_attribute(DATA::KEY).ok_or_else(|| {
                EventError::AttributeRetrieval(format!(
                    "Attribute {} not present",
                    DATA::KEY
                ))
            })?;
        encoded_value
            .parse()
            .map_err(|err: <Self::Value as FromStr>::Err| {
                EventError::AttributeRetrieval(err.to_string())
            })
    }
}

/// Read a raw (string encoded) attribute from an [event](Event)'s attributes.
pub trait RawReadFromEventAttributes<'value>: Sized {
    /// Check if the associated attribute is present in the provided event
    /// attributes.
    fn check_if_attribute_present<A>(attributes: &A) -> bool
    where
        A: AttributesMap;

    /// Read a string encoded attribute from the provided event attributes.
    fn raw_read_from_event_attributes<A>(
        attributes: &A,
    ) -> Result<&str, EventError>
    where
        A: AttributesMap;
}

impl<'value, DATA> RawReadFromEventAttributes<'value> for DATA
where
    DATA: EventAttributeEntry<'value>,
{
    #[inline]
    fn check_if_attribute_present<A>(attributes: &A) -> bool
    where
        A: AttributesMap,
    {
        attributes.is_attribute(DATA::KEY)
    }

    #[inline]
    fn raw_read_from_event_attributes<A>(
        attributes: &A,
    ) -> Result<&str, EventError>
    where
        A: AttributesMap,
    {
        attributes.retrieve_attribute(DATA::KEY).ok_or_else(|| {
            EventError::AttributeRetrieval(format!(
                "Attribute {} not present",
                DATA::KEY
            ))
        })
    }
}

/// Extend an [event](Event) with additional data.
pub trait ExtendEvent {
    /// Add additional data to the specified `event`.
    fn extend_event(self, event: &mut Event);
}

impl<E: ExtendEventAttributes> ExtendEvent for E {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        self.extend_event_attributes(&mut event.attributes);
    }
}

/// Extend an [`Event`] with block height information.
pub struct Height(pub BlockHeight);

impl EventAttributeEntry<'static> for Height {
    type Value = BlockHeight;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "height";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with transaction hash information.
pub struct TxHash(pub Hash);

impl EventAttributeEntry<'static> for TxHash {
    type Value = Hash;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "hash";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with log data.
pub struct Log(pub String);

impl EventAttributeEntry<'static> for Log {
    type Value = String;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "log";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with info data.
pub struct Info(pub String);

impl EventAttributeEntry<'static> for Info {
    type Value = String;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "info";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with `is_valid_masp_tx` data.
pub struct ValidMaspTx(pub usize);

impl EventAttributeEntry<'static> for ValidMaspTx {
    type Value = usize;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "is_valid_masp_tx";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with a new domain.
pub struct Domain(pub EventSegment);

impl ExtendEvent for Domain {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        let Self(domain) = self;
        event.event_type.domain = domain;
    }
}

#[cfg(test)]
mod event_composition_tests {
    use super::*;

    #[test]
    fn test_event_compose_basic() {
        let expected_attrs = {
            let mut attrs = HashMap::new();
            attrs.insert("log".to_string(), "this is sparta!".to_string());
            attrs.insert("height".to_string(), "300".to_string());
            attrs.insert("hash".to_string(), Hash::default().to_string());
            attrs
        };

        let base_event: Event = Event::applied_tx()
            .with(Log("this is sparta!".to_string()))
            .with(Height(300.into()))
            .with(TxHash(Hash::default()))
            .into();

        assert_eq!(base_event.attributes, expected_attrs);
    }

    #[test]
    fn test_event_compose_repeated() {
        let expected_attrs = {
            let mut attrs = HashMap::new();
            attrs.insert("log".to_string(), "dejavu".to_string());
            attrs
        };

        let base_event: Event = Event::applied_tx()
            .with(Log("dejavu".to_string()))
            .with(Log("dejavu".to_string()))
            .with(Log("dejavu".to_string()))
            .into();

        assert_eq!(base_event.attributes, expected_attrs);
    }

    #[test]
    fn test_event_compose_last_one_kept() {
        let expected_attrs = {
            let mut attrs = HashMap::new();
            attrs.insert("log".to_string(), "last".to_string());
            attrs
        };

        let base_event: Event = Event::applied_tx()
            .with(Log("fist".to_string()))
            .with(Log("second".to_string()))
            .with(Log("last".to_string()))
            .into();

        assert_eq!(base_event.attributes, expected_attrs);
    }

    #[test]
    fn test_domain_of_composed_event() {
        let composite_event = IbcEvent {
            event_type: "update_account".into(),
            attributes: Default::default(),
        }
        .with(Log("this is sparta!".to_string()))
        .with(Height(300.into()))
        .with(TxHash(Hash::default()));

        fn event_domain<E: EventToEmit>(_: &E) -> EventSegment {
            E::DOMAIN
        }

        assert_eq!(&*event_domain(&composite_event), "ibc");
    }

    #[test]
    fn test_event_compose_change_domain() {
        let composite: Event = Event::applied_tx()
            .with(Domain(EventSegment::new_static("sparta")))
            .into();

        assert_eq!(&*composite.event_type.domain, "sparta");
    }
}
