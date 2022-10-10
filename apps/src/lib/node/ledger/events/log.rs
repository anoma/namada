//! A log to store events emitted by `FinalizeBlock` calls in the ledger.
//!
//! The log is flushed every other `N` block heights, where `N` is a
//! configurable parameter.

mod dumb_queries;

use std::sync::{Arc, RwLock};

use namada::types::storage::BlockHeight;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task;

use crate::node::ledger::events::Event;

/// Instantiates a new event log and its associated machinery.
///
/// General usage flow:
///
///   1. Spawn a new asynchronous task, with a [`Logger`]
///      running on a loop.
///   2. Send new events to the [`Logger`] with a [`LogEntrySender`].
///      This will alter the state of the [`EventLog`].
///   3. Concurrently, other asynchronous tasks may access the
///      [`EventLog`] to check for new events.
pub fn new() -> (EventLog, Logger, LogEntrySender) {
    let (tx, rx) = mpsc::unbounded_channel();

    let log = EventLog::new();
    let logger = Logger {
        receiver: rx,
        log: log.clone(),
    };
    let sender = LogEntrySender { sender: tx };

    (log, logger, sender)
}

/// Represents an entry in the event log.
#[derive(Debug)]
pub struct LogEntry {
    /// The block height at which we emitted the events.
    pub block_height: BlockHeight,
    /// The events emitted by a `FinalizeBlock` call.
    pub events: Vec<Event>,
}

#[derive(Debug)]
struct LogNode {
    entry: LogEntry,
    next: Option<Arc<LogNode>>,
}

/// A log of [`Event`] instances emitted by `FinalizeBlock` calls,
/// in the ledger.
#[derive(Debug, Clone)]
pub struct EventLog {
    inner: Arc<EventLogInner>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct EventLogInner {
    /// A generator of notifications for RPC callers.
    notifier: event_listener::Event,
    /// Write protected data.
    lock: RwLock<EventLogInnerMux>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct EventLogInnerMux {
    /// The total number of entries in the log.
    num_entries: usize,
    /// The earliest block height in the event log.
    oldest_height: Option<BlockHeight>,
    /// Pointer to the freshest log entry.
    head: Option<Arc<LogNode>>,
}

/// An iterator over the [`Event`] instances in the
/// event log, matching a given [`Query`].
pub struct EventLogIterator<'a> {
    /// The current index pointing at the events in the `node` field.
    index: usize,
    /// A query to filter out events.
    query: dumb_queries::QueryMatcher<'a>,
    /// A pointer to one of the event log's entries.
    node: Option<Arc<LogNode>>,
}

impl<'a> Iterator for EventLogIterator<'a> {
    type Item = Event;

    fn next(&mut self) -> Option<Self::Item> {
        Some(loop {
            let node = self.node.as_ref()?;
            match node.entry.events.get(self.index) {
                Some(event) => {
                    self.index += 1;
                    if self.query.matches(event) {
                        break event.clone();
                    }
                }
                None => {
                    self.index = 0;
                    self.node = node.next.clone();
                }
            }
        })
    }
}

impl EventLog {
    /// Returns a new iterator over this [`EventLog`], if the
    /// given `query` is valid.
    pub fn iter<'a>(&self, query: &'a str) -> Option<EventLogIterator<'a>> {
        let query = dumb_queries::QueryMatcher::parse(query)?;
        let node = {
            let log = self.inner.lock.read().unwrap();
            log.head.clone()
        };
        Some(EventLogIterator {
            query,
            node,
            index: 0,
        })
    }

    /// Creates a new event log.
    fn new() -> Self {
        Self {
            inner: Arc::new(EventLogInner {
                notifier: event_listener::Event::new(),
                lock: RwLock::new(EventLogInnerMux {
                    num_entries: 0,
                    oldest_height: None,
                    head: None,
                }),
            }),
        }
    }

    /// Prune the event log, ejecting old [`Event`] instances.
    fn prune(&self) {
        // TODO
    }

    /// Add a new entry to the log.
    fn add(&self, entry: LogEntry) {
        let _ = entry;
        // TODO
    }
}

/// Receives new entries from a [`LogEntrySender`], and logs them in the
/// [`EventLog`].
#[derive(Debug)]
pub struct Logger {
    log: EventLog,
    receiver: UnboundedReceiver<LogEntry>,
}

impl Logger {
    /// Receive new events from a `FinalizeBlock` call, and log them.
    ///
    /// We should use this method in a loop, such as:
    ///
    /// ```ignore
    /// let mut logger: Logger = /* ... */;
    ///
    /// loop {
    ///     if logger.log_new_entry().await.is_none() {
    ///         /* handle errors */
    ///     }
    /// }
    /// ```
    pub async fn log_new_entry(&mut self) -> Option<()> {
        task::block_in_place(|| self.log.prune());
        let entry = self.receiver.recv().await?;
        task::block_in_place(move || self.log.add(entry));
        Some(())
    }

    /// Call [`Self::log_new_entry`] repeatedly.
    pub async fn run(&mut self) -> Option<()> {
        loop {
            self.log_new_entry().await?;
        }
    }
}

/// Utility struct to log new entries in the ledger's [`EventLog`].
///
/// A [`LogEntrySender`] always has an associated [`Logger`],
/// which will receive log entries from the same sender and
/// log them in the [`EventLog`].
#[derive(Debug, Clone)]
pub struct LogEntrySender {
    sender: UnboundedSender<LogEntry>,
}

impl LogEntrySender {
    /// Send a new [`LogEntry`] to a [`Logger`].
    ///
    /// This call will fail if the associated [`Logger`] has been dropped.
    #[inline]
    pub fn send_new_entry(&self, entry: LogEntry) -> Option<()> {
        self.sender.send(entry).ok()
    }
}
