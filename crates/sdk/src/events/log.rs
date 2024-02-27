//! A log to store events emitted by `FinalizeBlock` calls in the ledger.
//!
//! The log can only hold `N` events at a time, where `N` is a configurable
//! parameter. If the log is holding `N` events, and a new event is logged,
//! old events are pruned.
use circular_queue::CircularQueue;

use crate::events::Event;

pub mod dumb_queries;

/// Parameters to configure the pruning of the event log.
#[derive(Debug, Copy, Clone)]
pub struct Params {
    /// Soft limit on the maximum number of events the event log can hold.
    ///
    /// If the number of events in the log exceeds this value, the log
    /// will be pruned.
    pub max_log_events: usize,
}

impl Default for Params {
    fn default() -> Self {
        // TODO: tune the default params
        Self {
            max_log_events: 50000,
        }
    }
}

/// Represents a log of [`Event`] instances emitted by
/// `FinalizeBlock` calls, in the ledger.
#[derive(Debug)]
pub struct EventLog {
    queue: CircularQueue<Event>,
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl EventLog {
    /// Return a new event log.
    pub fn new(params: Params) -> Self {
        Self {
            queue: CircularQueue::with_capacity(params.max_log_events),
        }
    }

    /// Log a new batch of events into the event log.
    pub fn log_events<E>(&mut self, events: E)
    where
        E: IntoIterator<Item = Event>,
    {
        let mut num_entries = 0;
        for event in events.into_iter() {
            self.queue.push(event);
            num_entries += 1;
        }
        tracing::debug!(num_entries, "Added new entries to the event log");
    }

    /// Returns a new iterator over this [`EventLog`].
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &Event> {
        self.queue.iter()
    }

    /// Returns a filtering iterator over this [`EventLog`].
    #[inline]
    pub fn iter_with_matcher(
        &self,
        matcher: dumb_queries::QueryMatcher,
    ) -> impl Iterator<Item = &Event> {
        self.queue
            .iter()
            .filter(move |&event| matcher.matches(event))
    }
}

#[cfg(test)]
mod tests {
    use namada_core::hash::Hash;

    use super::*;
    use crate::events::{EventLevel, EventType};

    const HASH: &str =
        "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";

    /// An accepted tx hash query.
    macro_rules! accepted {
        ($hash:expr) => {
            dumb_queries::QueryMatcher::accepted(Hash::try_from($hash).unwrap())
        };
    }

    /// Return a vector of mock `FinalizeBlock` events.
    fn mock_tx_events(hash: &str) -> Vec<Event> {
        let event_1 = Event {
            event_type: EventType::Accepted,
            level: EventLevel::Block,
            attributes: {
                let mut attrs = std::collections::HashMap::new();
                attrs.insert("hash".to_string(), hash.to_string());
                attrs
            },
        };
        let event_2 = Event {
            event_type: EventType::Applied,
            level: EventLevel::Block,
            attributes: {
                let mut attrs = std::collections::HashMap::new();
                attrs.insert("hash".to_string(), hash.to_string());
                attrs
            },
        };
        vec![event_1, event_2]
    }

    /// Test adding a couple of events to the event log, and
    /// reading those events back.
    #[test]
    fn test_log_add() {
        const NUM_HEIGHTS: usize = 4;

        let mut log = EventLog::new(Params::default());

        // add new events to the log
        let events = mock_tx_events(HASH);

        for _ in 0..NUM_HEIGHTS {
            log.log_events(events.clone());
        }

        // inspect log
        let events_in_log: Vec<_> =
            log.iter_with_matcher(accepted!(HASH)).cloned().collect();

        assert_eq!(events_in_log.len(), NUM_HEIGHTS);

        for event in events_in_log {
            assert_eq!(events[0], event);
        }
    }

    /// Test pruning old events from the log.
    #[test]
    fn test_log_prune() {
        const LOG_CAP: usize = 4;

        // log cap has to be a multiple of two
        // for this test
        if LOG_CAP < 2 || LOG_CAP & 1 != 0 {
            panic!();
        }

        const MATCHED_EVENTS: usize = LOG_CAP / 2;

        let mut log = EventLog::new(Params {
            max_log_events: LOG_CAP,
        });

        // completely fill the log with events
        //
        // `mock_tx_events` returns 2 events, so
        // we do `LOG_CAP / 2` iters to fill the log
        let events = mock_tx_events(HASH);
        assert_eq!(events.len(), 2);

        for _ in 0..(LOG_CAP / 2) {
            log.log_events(events.clone());
        }

        // inspect log - it should be full
        let events_in_log: Vec<_> =
            log.iter_with_matcher(accepted!(HASH)).cloned().collect();

        assert_eq!(events_in_log.len(), MATCHED_EVENTS);

        for event in events_in_log {
            assert_eq!(events[0], event);
        }

        // add a new APPLIED event to the log,
        // pruning the first ACCEPTED event we added
        log.log_events(Some(events[1].clone()));

        let events_in_log: Vec<_> =
            log.iter_with_matcher(accepted!(HASH)).cloned().collect();

        const ACCEPTED_EVENTS: usize = MATCHED_EVENTS - 1;
        assert_eq!(events_in_log.len(), ACCEPTED_EVENTS);

        for event in events_in_log {
            assert_eq!(events[0], event);
        }
    }
}
