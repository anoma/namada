//! A log to store events emitted by `FinalizeBlock` calls in the ledger.
//!
//! The log is flushed every other `N` block heights, where `N` is a
//! configurable parameter.

use std::sync::{Arc, RwLock, RwLockReadGuard};

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task;

use crate::facade::tendermint_rpc::query::Query;
use crate::node::ledger::events::Event;

/// Instantiates a new event log and its associated machinery.
pub fn new_log() -> (EventLog, EventLogger, EventSender) {
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
#[allow(dead_code)]
pub struct EventLogIterator<'it> {
    index: usize,
    guard: RwLockReadGuard<'it, Vec<Event>>,
    query: Query,
}

impl EventLog {
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
    pub async fn log_events(&mut self) -> Option<()> {
        task::block_in_place(|| self.log.prune());
        let events = self.receiver.recv().await?;
        task::block_in_place(move || self.log.add(events));
        Some(())
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
