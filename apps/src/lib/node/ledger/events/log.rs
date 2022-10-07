//! A log to store events emitted by `FinalizeBlock` calls in the ledger.
//!
//! The log is flushed every other `N` block heights, where `N` is a
//! configurable parameter.

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::node::ledger::events::Event;

/// Instantiates a new event log and its associated machinery.
pub fn new_log() -> (EventLog, EventLogger, EventSender) {
    let (tx, rx) = mpsc::unbounded_channel();

    let logger = EventLogger { receiver: rx };
    let sender = EventSender { sender: tx };

    (todo!(), logger, sender)
}

/// A log of [`Event`] instances emitted by `FinalizeBlock` calls,
/// in the ledger.
#[derive(Debug)]
pub struct EventLog;

/// Receives events from an [`EventSender`], and logs them to the
/// [`EventLog`].
#[derive(Debug)]
pub struct EventLogger {
    log: EventLog,
    receiver: UnboundedReceiver<Vec<Event>>,
}

impl EventLogger {
    /// Receive new events from a `FinalizeBlock` call, and log them.
    pub async fn log_events(&mut self) -> Option<Vec<Event>> {
        self.receiver.recv().await
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
