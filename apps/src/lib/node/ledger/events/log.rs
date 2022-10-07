//! A log to store events emitted by `FinalizeBlock` calls in the ledger.
//!
//! The log is flushed every other `N` block heights, where `N` is a
//! configurable parameter.

mod dumb_queries;

use std::sync::{Arc, RwLock, RwLockReadGuard};

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task;

use crate::node::ledger::events::Event;

/// Instantiates a new event log and its associated machinery.
pub fn new() -> (EventLog, EventLogger, EventSender) {
    let (tx, rx) = mpsc::unbounded_channel();

    let log = EventLog::new();
    let logger = EventLogger {
        receiver: rx,
        log: log.clone(),
    };
    let sender = EventSender { sender: tx };

    (log, logger, sender)
}

/// A log of [`Event`] instances emitted by `FinalizeBlock` calls,
/// in the ledger.
#[derive(Debug, Clone)]
pub struct EventLog {
    // TODO: this storage repr is a placeholder! we need to
    // prune events, and for that we need to keep track of their
    // block height; additionally, we want to improve the efficiency
    // of the log, since we might be logging many events per block,
    // which can constitute a dos attack on us.
    //
    // we should strive to be more read than write friendly, to
    // support many concurrent readers of log events.
    inner: Arc<RwLock<Vec<Event>>>,
}

/// An iterator over the [`Event`] instances in the
/// event log, matching a given [`Query`].
pub struct EventLogIterator<'a> {
    index: usize,
    guard: RwLockReadGuard<'a, Vec<Event>>,
    query: dumb_queries::QueryMatcher<'a>,
}

impl<'a> Iterator for EventLogIterator<'a> {
    type Item = Event;

    fn next(&mut self) -> Option<Self::Item> {
        let event = loop {
            let event = self.guard.get(self.index)?;
            self.index += 1;

            if self.query.matches(event) {
                break event;
            }
        };
        Some(event.clone())
    }
}

impl EventLog {
    /// Returns a new iterator over this [`EventLog`], if the
    /// given `query` is valid.
    pub fn iter<'a>(&'a self, query: &'a str) -> Option<EventLogIterator<'a>> {
        let query = dumb_queries::QueryMatcher::parse(query)?;
        Some(EventLogIterator {
            query,
            index: 0,
            guard: self.inner.read().unwrap(),
        })
    }

    /// Creates a new event log.
    fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Prune the event log, ejecting old [`Event`] instances.
    fn prune(&self) {
        // TODO
    }

    /// Add new events to the log.
    fn add(&self, events: Vec<Event>) {
        let mut buf = self.inner.write().unwrap();
        buf.extend(events);
    }
}

/// Receives events from an [`EventSender`], and logs them to the
/// [`EventLog`].
#[derive(Debug)]
pub struct EventLogger {
    log: EventLog,
    receiver: UnboundedReceiver<Vec<Event>>,
}

impl EventLogger {
    /// Receive new events from a `FinalizeBlock` call, and log them.
    ///
    /// We should use this method in a loop, such as:
    ///
    /// ```ignore
    /// let mut logger: EventLogger = /* ... */;
    ///
    /// loop {
    ///     if logger.log_new_events_batch().await.is_none() {
    ///         /* handle errors */
    ///     }
    /// }
    /// ```
    pub async fn log_new_events_batch(&mut self) -> Option<()> {
        task::block_in_place(|| self.log.prune());
        let events = self.receiver.recv().await?;
        task::block_in_place(move || self.log.add(events));
        Some(())
    }

    /// Call [`Self::log_new_events_batch`] repeatedly.
    pub async fn run(&mut self) -> Option<()> {
        loop {
            self.log_new_events_batch().await?;
        }
    }
}

/// Utility struct to log events in the ledger's [`EventLog`].
///
/// An [`EventSender`] always has an associated [`EventLogger`],
/// which will receive events from the same sender and log them
/// in the [`EventLog`].
#[derive(Debug, Clone)]
pub struct EventSender {
    sender: UnboundedSender<Vec<Event>>,
}

impl EventSender {
    /// Send new events to an [`EventLogger`].
    ///
    /// This call will fail if the associated [`EventLogger`] has been dropped.
    #[inline]
    pub fn send_events(&self, events: Vec<Event>) -> Option<()> {
        self.sender.send(events).ok()
    }
}
