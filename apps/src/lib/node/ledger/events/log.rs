//! A log to store events emitted by `FinalizeBlock` calls in the ledger.
//!
//! The log can only hold `N` events at a time, where `N` is a configurable
//! parameter. If the log is holding `N` events, and a new event is logged,
//! old events are pruned.

use std::default::Default;

use circular_queue::CircularQueue;

use crate::node::ledger::events::Event;

pub mod dumb_queries;

/// Errors specific to [`EventLog`] operations.
#[derive(Debug)]
pub enum Error {
    /// We failed to parse a Tendermint query.
    InvalidQuery,
}

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

impl EventLog {
    /// Return a new event log.
    pub fn new(params: Params) -> Self {
        Self {
            queue: CircularQueue::with_capacity(params.max_log_events),
        }
    }

    /// Log a new batch of events into the event log.
    pub fn log_events<'e, E>(&mut self, events: E)
    where
        E: IntoIterator<Item = &'e Event> + 'e,
    {
        let mut num_entries = 0;
        for event in events.into_iter().cloned() {
            self.queue.push(event);
            num_entries += 1;
        }
        tracing::debug!(num_entries, "Added new entries to the event log");
    }

    /// Returns a new iterator over this [`EventLog`], if the
    /// given `query` is valid.
    pub fn try_iter<'query, 'log>(
        &'log self,
        query: &'query str,
    ) -> Result<impl Iterator<Item = &'log Event> + 'query, Error>
    where
        // the log should outlive the query
        'log: 'query,
    {
        let matcher =
            dumb_queries::QueryMatcher::parse(query).ok_or_else(|| {
                tracing::debug!(query, "Invalid Tendermint query");
                Error::InvalidQuery
            })?;
        Ok(self.iter_with_matcher(matcher))
    }

    /// Just like [`EventLog::try_iter`], but uses a pre-compiled
    /// query matcher.
    #[inline]
    pub fn iter_with_matcher<'query, 'log: 'query>(
        &'log self,
        matcher: dumb_queries::QueryMatcher<'query>,
    ) -> impl Iterator<Item = &'log Event> + 'query {
        self.queue
            .iter()
            .filter(move |event| matcher.matches(event))
    }
}
