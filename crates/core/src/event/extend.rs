//! Extend [events](Event) with additional fields.

use super::*;
use crate::hash::Hash;
use crate::storage::BlockHeight;

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

/// Extend an [event](Event) with additional fields.
pub trait ExtendEvent {
    /// Add additional fields to the specified `event`.
    fn extend_event(self, event: &mut Event);
}

/// Leaves an [`Event`] as is.
pub struct WithNoOp;

impl ExtendEvent for WithNoOp {
    #[inline]
    fn extend_event(self, _: &mut Event) {}
}

/// Extend an [`Event`] with block height information.
pub struct Height(pub BlockHeight);

impl ExtendEvent for Height {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        let Self(height) = self;
        event["height"] = height.to_string();
    }
}

/// Extend an [`Event`] with transaction hash information.
pub struct TxHash(pub Hash);

impl ExtendEvent for TxHash {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        let Self(hash) = self;
        event["hash"] = hash.to_string();
    }
}

/// Extend an [`Event`] with log data.
pub struct Log(pub String);

impl ExtendEvent for Log {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        let Self(log) = self;
        event["log"] = log;
    }
}

/// Extend an [`Event`] with info data.
pub struct Info(pub String);

impl ExtendEvent for Info {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        let Self(info) = self;
        event["info"] = info;
    }
}

/// Extend an [`Event`] with `is_valid_masp_tx` data.
pub struct ValidMaspTx(pub usize);

impl ExtendEvent for ValidMaspTx {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        let Self(masp_tx_index) = self;
        event["is_valid_masp_tx"] = masp_tx_index.to_string();
    }
}

#[cfg(test)]
mod event_composition_tests {
    use std::collections::HashMap;

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
}
