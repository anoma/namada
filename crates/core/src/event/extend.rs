//! Extend [events](Event) with additional fields.

use super::*;
use crate::hash::Hash;
use crate::storage::BlockHeight;

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

    /// Compose this event with new data.
    pub const fn compose<NEW>(self, data: NEW) -> CompositeEvent<NEW, Self> {
        CompositeEvent::new(self, data)
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
pub struct WithBlockHeight(pub BlockHeight);

impl ExtendEvent for WithBlockHeight {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        let Self(height) = self;
        event["height"] = height.to_string();
    }
}

/// Extend an [`Event`] with transaction hash information.
pub struct WithTxHash(pub Hash);

impl ExtendEvent for WithTxHash {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        let Self(hash) = self;
        event["hash"] = hash.to_string();
    }
}

/// Extend an [`Event`] with log data.
pub struct WithLog(pub String);

impl ExtendEvent for WithLog {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        let Self(log) = self;
        event["log"] = log;
    }
}

/// Defer the extension of an [`Event`] to other
/// implementations of [`ExtendEvent`].
pub struct WithDeferredData<THIS, NEXT> {
    this: THIS,
    next: NEXT,
}

impl<THIS> WithDeferredData<THIS, WithNoOp> {
    /// Begin composing a batch of [`ExtendEvent`] implementations.
    pub const fn begin(data: THIS) -> Self {
        Self {
            this: data,
            next: WithNoOp,
        }
    }
}

impl<THIS, NEXT> WithDeferredData<THIS, NEXT> {
    /// Add to the batch of [`ExtendEvent`] implementations.
    pub const fn compose<NEW>(self, data: NEW) -> WithDeferredData<NEW, Self> {
        WithDeferredData {
            this: data,
            next: self,
        }
    }
}

impl<THIS, NEXT> ExtendEvent for WithDeferredData<THIS, NEXT>
where
    THIS: ExtendEvent,
    NEXT: ExtendEvent,
{
    fn extend_event(self, event: &mut Event) {
        self.this.extend_event(event);
        self.next.extend_event(event);
    }
}

#[cfg(test)]
mod event_composition_tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn test_with_deferred_data_basic() {
        let expected_attrs = {
            let mut attrs = HashMap::new();
            attrs.insert("log".to_string(), "this is sparta!".to_string());
            attrs.insert("height".to_string(), "300".to_string());
            attrs.insert("hash".to_string(), Hash::default().to_string());
            attrs
        };

        let mut base_event = Event::applied_tx();
        base_event.extend(
            WithDeferredData::begin(WithLog("this is sparta!".to_string()))
                .compose(WithBlockHeight(300.into()))
                .compose(WithTxHash(Hash::default())),
        );

        assert_eq!(base_event.attributes, expected_attrs);
    }

    #[test]
    fn test_with_deferred_repeated() {
        let expected_attrs = {
            let mut attrs = HashMap::new();
            attrs.insert("log".to_string(), "dejavu".to_string());
            attrs
        };

        let mut base_event = Event::applied_tx();
        base_event.extend(
            WithDeferredData::begin(WithLog("dejavu".to_string()))
                .compose(WithLog("dejavu".to_string()))
                .compose(WithLog("dejavu".to_string()))
                .compose(WithLog("dejavu".to_string())),
        );

        assert_eq!(base_event.attributes, expected_attrs);
    }

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
            .compose(WithLog("this is sparta!".to_string()))
            .compose(WithBlockHeight(300.into()))
            .compose(WithTxHash(Hash::default()))
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
            .compose(WithLog("dejavu".to_string()))
            .compose(WithLog("dejavu".to_string()))
            .compose(WithLog("dejavu".to_string()))
            .into();

        assert_eq!(base_event.attributes, expected_attrs);
    }
}
