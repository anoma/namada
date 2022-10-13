//! A log to store events emitted by `FinalizeBlock` calls in the ledger.
//!
//! The log is flushed every other `N` block heights, or every other `E`
//! `FinalizeBlock` events, where `N` and `E` are configurable parameters.

pub mod dumb_queries;

use std::default::Default;
use std::ops::ControlFlow;
use std::sync::{Arc, RwLock};

use namada::types::storage::BlockHeight;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::Instant;

use crate::node::ledger::events::Event;

/// Run a CPU-bound task without blocking the Tokio runtime.
macro_rules! block_in_place {
    ($expr:expr) => {{
        // we need this because `tokio_test` panics if we
        // call `tokio::task::block_in_place()`
        #[cfg(test)]
        {
            $expr
        }
        #[cfg(not(test))]
        {
            ::tokio::task::block_in_place(|| $expr)
        }
    }};
}

/// Parameters to configure the pruning of the event log.
#[derive(Debug, Copy, Clone)]
pub struct Params {
    /// Soft limit on the maximum number of events the event log can hold.
    ///
    /// If the number of events in the log exceeds this value, the log
    /// will be pruned.
    pub max_log_events: usize,
    /// Soft limit on the number of entries the event log can hold.
    ///
    /// If the difference between the newest log entry and the oldest's
    /// block heights is greater than this value, the log will be pruned.
    pub log_block_height_diff: u64,
}

impl Default for Params {
    fn default() -> Self {
        // TODO: tune the default params
        Self {
            max_log_events: 50000,
            log_block_height_diff: 1000,
        }
    }
}

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
pub fn new(params: Params) -> (EventLog, Logger, LogEntrySender) {
    let (tx, rx) = mpsc::unbounded_channel();

    let log = EventLog::new(params);
    let logger = Logger {
        receiver: rx,
        log: log.clone(),
    };
    let sender = LogEntrySender { sender: tx };

    (log, logger, sender)
}

/// Represents an entry in the event log.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// The block height at which we emitted the events.
    pub block_height: BlockHeight,
    /// The events emitted by a `FinalizeBlock` call.
    pub events: Vec<Event>,
}

/// Represents a node in the linked list of log entries.
#[derive(Debug)]
struct LogNode {
    entry: LogEntry,
    next: Option<Arc<LogNode>>,
}

impl LogNode {
    /// Return an iterator over the given linked list
    /// of [`LogNode`] instances.
    fn iter(node: Option<&Arc<LogNode>>) -> LogNodeIter<'_> {
        LogNodeIter { node }
    }
}

/// Iterator over [`LogNode`] instances in
/// the same linked list.
#[derive(Debug)]
struct LogNodeIter<'a> {
    node: Option<&'a Arc<LogNode>>,
}

impl<'a> Iterator for LogNodeIter<'a> {
    type Item = &'a Arc<LogNode>;

    fn next(&mut self) -> Option<&'a Arc<LogNode>> {
        self.node.take().map(|node| {
            self.node = node.next.as_ref();
            node
        })
    }
}

/// Represents a log of [`Event`] instances emitted by
/// `FinalizeBlock` calls, in the ledger.
///
/// __INVARIANT:__ All logged events should be ordered
/// in reverse by the shell's block height at the time
/// of calling `FinalizeBlock`.
#[derive(Debug, Clone)]
pub struct EventLog {
    inner: Arc<EventLogInner>,
}

/// Contains a snapshot of the state of the [`EventLog`]
/// at some fixed point in time.
#[derive(Debug, Clone)]
pub struct EventLogSnapshot {
    oldest_height: BlockHeight,
    num_events: usize,
    head: Arc<LogNode>,
}

/// Container for an event notifier and a lock, holding [`EventLog`] data.
#[derive(Debug)]
struct EventLogInner {
    /// Parameters to configure log pruning.
    params: Params,
    /// A generator of notifications for RPC callers.
    notifier: event_listener::Event,
    /// Write protected data.
    lock: RwLock<EventLogInnerMux>,
}

/// Data which needs lock protection, in the [`EventLog`].
#[derive(Debug, Default)]
struct EventLogInnerMux {
    /// The total number of events stored in the log.
    ///
    /// This value is the sum of every batch of events in
    /// each entry in the log.
    num_events: usize,
    /// The earliest block height in the event log.
    oldest_height: BlockHeight,
    /// Pointer to the freshest log entry.
    head: Option<Arc<LogNode>>,
}

/// Represents an iterator over the [`Event`] instances in the
/// event log, matching a given Tendermint-like query.
pub struct EventLogIter<'n, 'q> {
    /// The current index pointing at the events in the `node` field.
    index: usize,
    /// A query to filter out events.
    query: dumb_queries::QueryMatcher<'q>,
    /// A pointer to one of the event log's entries.
    node: Option<&'n Arc<LogNode>>,
}

impl<'n, 'q> Iterator for EventLogIter<'n, 'q> {
    type Item = &'n Event;

    fn next(&mut self) -> Option<Self::Item> {
        Some(loop {
            let node = self.node.as_ref()?;
            match node.entry.events.get(self.index) {
                Some(event) => {
                    self.index += 1;
                    if self.query.matches(event) {
                        break event;
                    }
                }
                None => {
                    self.index = 0;
                    self.node = node.next.as_ref();
                }
            }
        })
    }
}

impl EventLogSnapshot {
    /// Returns a new iterator over this [`EventLogSnapshot`], if the
    /// given `query` is valid.
    pub fn try_iter<'n, 'q>(
        &'n self,
        query: &'q str,
    ) -> Result<EventLogIter<'n, 'q>, Error> {
        let matcher =
            dumb_queries::QueryMatcher::parse(query).ok_or_else(|| {
                tracing::debug!(query, "Invalid Tendermint query");
                Error::InvalidQuery
            })?;
        Ok(self.iter_with_matcher(matcher))
    }

    /// Just like [`EventLogSnapshot::try_iter`], but uses a pre-compiled
    /// query matcher.
    #[inline]
    pub fn iter_with_matcher<'n, 'q>(
        &'n self,
        matcher: dumb_queries::QueryMatcher<'q>,
    ) -> EventLogIter<'n, 'q> {
        EventLogIter {
            index: 0,
            query: matcher,
            node: Some(&self.head),
        }
    }

    /// Return the [`BlockHeight`] of the oldest event batch
    /// in the [`EventLogSnapshot`].
    #[inline]
    pub fn oldest_height(&self) -> BlockHeight {
        self.oldest_height
    }

    /// Return the number of events in the [`EventLogSnapshot`].
    #[inline]
    pub fn num_events(&self) -> usize {
        self.num_events
    }
}

/// Errors specific to [`EventLog`] operations.
#[derive(Debug)]
pub enum Error {
    /// We failed to parse a Tendermint query.
    InvalidQuery,
    /// The event log has no entries.
    EmptyLog,
    /// We timed out waiting for log entries.
    Timeout,
}

impl EventLog {
    /// Snapshot the current state of the event log, and return it.
    /// This operation may fail if the event log has no entries.
    ///
    /// For as long as the caller holds an instance of an
    /// [`EventLogSnapshot`], the state of the [`EventLog`]
    /// at the time of calling this method can be accessed.
    pub fn snapshot(&self) -> Result<EventLogSnapshot, Error> {
        let log = block_in_place!(self.inner.lock.read()).unwrap();
        log.head
            .clone()
            .map(|head| EventLogSnapshot {
                head,
                num_events: log.num_events,
                oldest_height: log.oldest_height,
            })
            .ok_or(Error::EmptyLog)
    }

    /// Waits up to `deadline` for new events, and if it succeeds,
    /// returns a new snapshot of the log.
    pub async fn wait_snapshot(
        &self,
        deadline: Instant,
    ) -> Result<EventLogSnapshot, Error> {
        tokio::time::timeout_at(deadline, async move {
            loop {
                self.inner.notifier.listen().await;

                if let Ok(snapshot) = self.snapshot() {
                    break snapshot;
                }
            }
        })
        .await
        .map_or_else(
            // we timed out from `tokio::time::timeout_at`
            |_| Err(Error::Timeout),
            // we did not time out; return the snapshot
            // of the log
            Ok,
        )
    }

    /// Creates a new event log.
    fn new(params: Params) -> Self {
        Self {
            inner: Arc::new(EventLogInner {
                params,
                notifier: event_listener::Event::new(),
                lock: RwLock::new(EventLogInnerMux {
                    num_events: 0,
                    oldest_height: 0.into(),
                    head: None,
                }),
            }),
        }
    }

    /// Prune the event log, ejecting old [`Event`] instances.
    fn prune(
        &self,
        head: Option<Arc<LogNode>>,
        num_events: usize,
        height_diff: u64,
    ) {
        if num_events > self.inner.params.max_log_events {
            let keep_events = calc_num_of_kept_events(num_events);
            tracing::debug!(
                max_log_events = self.inner.params.max_log_events,
                events_to_keep = keep_events,
                previous_count = num_events,
                "Pruning events from the event log",
            );
            let snapshot = if keep_events > 0 {
                self.prune_too_many_events(head, keep_events)
            } else {
                tracing::debug!("Clearing event log");
                None
            };
            self.inner.lock.write().unwrap().install_snapshot(snapshot);
            return;
        }
        if height_diff > self.inner.params.log_block_height_diff {
            let nodes_to_keep = calc_num_of_kept_ents(height_diff);
            tracing::debug!(
                max_height_diff = self.inner.params.log_block_height_diff,
                nodes_to_keep,
                height_diff,
                "Pruning entries from the event log",
            );
            let snapshot = if nodes_to_keep > 0 {
                self.prune_old_events(head, nodes_to_keep)
            } else {
                tracing::debug!("Clearing event log");
                None
            };
            self.inner.lock.write().unwrap().install_snapshot(snapshot);
        }
    }

    /// Prune events from the log, keeping at most `max_events`
    /// of the most recent events.
    fn prune_too_many_events(
        &self,
        head: Option<Arc<LogNode>>,
        max_events: usize,
    ) -> Option<EventLogSnapshot> {
        self.prune_on_condition(head, |_, total_events| {
            if total_events <= max_events {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(())
            }
        })
    }

    /// Prune nodes and their events from the log, keeping only as many
    /// as `nodes_to_keep`.
    fn prune_old_events(
        &self,
        head: Option<Arc<LogNode>>,
        nodes_to_keep: u64,
    ) -> Option<EventLogSnapshot> {
        self.prune_on_condition(head, |no_nodes, _| {
            if no_nodes <= nodes_to_keep {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(())
            }
        })
    }

    /// Prune all events in the log whose oldest parent
    /// node evalutes to false, when passed to `predicate`.
    fn prune_on_condition<P>(
        &self,
        head: Option<Arc<LogNode>>,
        mut predicate: P,
    ) -> Option<EventLogSnapshot>
    where
        P: FnMut(u64, usize) -> ControlFlow<()>,
    {
        // allocate a new list, and drop
        // the old one
        let mut total_ents = 0;
        let mut total_events = 0;
        let mut oldest_height = 0.into();

        LogNode::iter(head.as_ref())
            // filter out events in the log
            .take_while(|n| {
                let new_total_events = total_events + n.entry.events.len();
                total_ents += 1;
                match predicate(total_ents, new_total_events) {
                    ControlFlow::Continue(()) => {
                        total_events = new_total_events;
                        oldest_height = n.entry.block_height;
                        true
                    }
                    ControlFlow::Break(()) => false,
                }
            })
            // build vec of new log nodes, all pointing to a null next node
            .map(|n| {
                Arc::new(LogNode {
                    entry: n.entry.clone(),
                    next: None,
                })
            })
            .collect::<Vec<_>>()
            // iterate the vec in reverse order, to link the nodes together in
            // the correct order, e.g.: next <- head
            .into_iter()
            .rev()
            .reduce(|next, mut head| {
                Arc::get_mut(&mut head)
                    .expect("There is only one live instance of this Arc")
                    .next = Some(next);
                head
            })
            .map(|head| EventLogSnapshot {
                head,
                num_events: total_events,
                oldest_height,
            })
    }

    /// Add a new entry to the log.
    fn add(&self, entry: LogEntry) {
        // do not log zero length event vecs
        if entry.events.is_empty() {
            tracing::debug!(?entry, "Rejected log entry with empty events");
            return;
        }

        // update the log head
        let (head, events, diff) = {
            let mut log = self.inner.lock.write().unwrap();
            let height_respects_log_invariant = {
                log.head
                    .as_ref()
                    .map(|head| entry.block_height > head.entry.block_height)
                    // if the log is empty, we can add whatever height
                    // we want to the log
                    .unwrap_or_else(|| {
                        log.oldest_height = entry.block_height;
                        true
                    })
            };
            if !height_respects_log_invariant {
                // drop entries whose block height is not
                // higher than the log head's height
                tracing::debug!(
                    ?entry,
                    "Rejected log entry with invalid block height",
                );
                return;
            } else {
                tracing::debug!(?entry, "Adding new entry to the event log");
            }
            let height_diff = entry.block_height.0 - log.oldest_height.0;
            log.num_events += entry.events.len();
            log.head = Some(Arc::new(LogNode {
                entry,
                next: log.head.take(),
            }));
            let new_head = log.head.clone();
            (new_head, log.num_events, height_diff)
        };

        // notify all event listeners
        self.inner.notifier.notify(usize::MAX);

        // we don't need to hold a lock to check
        // if the log needs to be pruned
        self.prune(head, events, diff);
    }
}

impl EventLogInnerMux {
    /// Modifies the state of the [`EventLogInnerMux`] with the provided
    /// [`EventLogSnapshot`].
    fn install_snapshot(&mut self, snapshot: Option<EventLogSnapshot>) {
        if let Some(snapshot) = snapshot {
            self.oldest_height = snapshot.oldest_height;
            self.num_events = snapshot.num_events;
            self.head = Some(snapshot.head);
        } else {
            *self = Default::default();
        }
    }
}

/// Receiver of new entries from a [`LogEntrySender`].
///
/// Received entries are logged to an [`EventLog`].
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
        let entry = self.receiver.recv().await?;
        block_in_place!(self.log.add(entry));
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

/// Calculate the number of events to keep, when we prune
/// the event log.
///
/// We parameterize this computation with the current number
/// of events in the log.
const fn calc_num_of_kept_events(curr: usize) -> usize {
    3 * curr / 4
}

/// Calculate the number of log entries to keep, when we
/// prune the event log.
///
/// We parameterize this computation with the difference
/// between the oldest and most recent block heights
/// stored in the log.
const fn calc_num_of_kept_ents(diff: u64) -> u64 {
    3 * diff / 4
}

#[cfg(test)]
mod tests {
    use tokio::time::{self, Duration};

    use super::*;
    use crate::node::ledger::events::{EventLevel, EventType};

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
    #[tokio::test]
    async fn test_log_add() {
        const NUM_HEIGHTS: u64 = 4;

        let (log, mut logger, sender) = new(Params::default());

        // send events to the logger
        let events = mock_tx_events("DEADBEEF");

        for height in 0..NUM_HEIGHTS {
            sender
                .send_new_entry(LogEntry {
                    block_height: height.into(),
                    events: events.clone(),
                })
                .unwrap();
        }

        // receive events in the logger, and log them
        // to the event log
        for _ in 0..NUM_HEIGHTS {
            logger.log_new_entry().await.unwrap();
        }

        // inspect log
        let events_in_log: Vec<_> = log
            .snapshot()
            .unwrap()
            .try_iter("tm.event='NewBlock' AND accepted.hash='DEADBEEF'")
            .unwrap()
            .cloned()
            .collect();

        assert_eq!(events_in_log.len(), NUM_HEIGHTS as usize);

        for i in 0..NUM_HEIGHTS {
            let i = i as usize;
            assert_eq!(events[0], events_in_log[i]);
        }
    }

    /// Test parallel log accesses.
    #[tokio::test]
    async fn test_parallel_log_reads() {
        const NUM_CONCURRENT_READERS: usize = 4;
        const NUM_HEIGHTS: u64 = 4;

        let (log, mut logger, sender) = new(Params::default());

        // send events to the logger
        let events = mock_tx_events("DEADBEEF");

        for height in 0..NUM_HEIGHTS {
            sender
                .send_new_entry(LogEntry {
                    block_height: height.into(),
                    events: events.clone(),
                })
                .unwrap();
        }

        // receive events in the logger, and log them
        // to the event log
        for _ in 0..NUM_HEIGHTS {
            logger.log_new_entry().await.unwrap();
        }

        // test reading the log in parallel
        let mut handles = vec![];

        for _ in 0..NUM_CONCURRENT_READERS {
            let log = log.clone();
            let events = events.clone();

            handles.push(std::thread::spawn(move || {
                let events_in_log: Vec<_> = log
                    .snapshot()
                    .unwrap()
                    .try_iter(
                        "tm.event='NewBlock' AND accepted.hash='DEADBEEF'",
                    )
                    .unwrap()
                    .cloned()
                    .collect();

                assert_eq!(events_in_log.len(), NUM_HEIGHTS as usize);

                for i in 0..NUM_HEIGHTS {
                    let i = i as usize;
                    assert_eq!(events[0], events_in_log[i]);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
    }

    /// Test that we reject log entries with no new events.
    #[tokio::test]
    async fn test_reject_empty_events() {
        let (log, mut logger, sender) = new(Params::default());

        sender
            .send_new_entry(LogEntry {
                block_height: 0.into(),
                events: vec![],
            })
            .unwrap();

        logger.log_new_entry().await.unwrap();

        // inspect log
        let locked_log = log.inner.lock.read().unwrap();

        assert!(locked_log.head.is_none());
        assert_eq!(locked_log.num_events, 0);
        assert_eq!(locked_log.oldest_height.0, 0);
    }

    /// Test that we reject log entries with invalid block heights.
    #[tokio::test]
    async fn test_reject_invalid_heights() {
        let (log, mut logger, sender) = new(Params::default());

        let events = mock_tx_events("DEADBEEF");

        sender
            .send_new_entry(LogEntry {
                block_height: 4.into(),
                events: events.clone(),
            })
            .unwrap();
        sender
            .send_new_entry(LogEntry {
                block_height: 0.into(),
                events: events.clone(),
            })
            .unwrap();
        logger.log_new_entry().await.unwrap();
        logger.log_new_entry().await.unwrap();

        // inspect log
        let locked_log = log.inner.lock.read().unwrap();

        assert!(locked_log.head.is_some());
        assert_eq!(locked_log.num_events, 2);
        assert_eq!(locked_log.oldest_height.0, 4);
    }

    /// Test that we prune the event log once the maximum
    /// number of configured stored events has been reached.
    #[tokio::test]
    async fn test_log_prune_on_max_events() {
        let (log, mut logger, sender) = new(Params {
            max_log_events: 4,
            log_block_height_diff: 9999,
        });

        let events = mock_tx_events("DEADBEEF");

        // the log can store up to 4 events,
        // so if we send 2 events we shouldn't
        // prune any of them
        sender
            .send_new_entry(LogEntry {
                block_height: 0.into(),
                events: events.clone(),
            })
            .unwrap();
        logger.log_new_entry().await.unwrap();

        // make sure these events landed in
        // the log, and that we didn't prune it
        {
            let locked_log = log.inner.lock.read().unwrap();
            assert!(locked_log.head.is_some());
            assert_eq!(locked_log.num_events, 2);
            assert_eq!(locked_log.oldest_height.0, 0);
        }

        // add 4 more events to the log - total = 6;
        // this should trigger a log prune
        sender
            .send_new_entry(LogEntry {
                block_height: 1.into(),
                events: events.clone(),
            })
            .unwrap();
        sender
            .send_new_entry(LogEntry {
                block_height: 2.into(),
                events,
            })
            .unwrap();
        logger.log_new_entry().await.unwrap();
        logger.log_new_entry().await.unwrap();

        // make sure we pruned the log;
        // we basically drop the last batch of events,
        // so 6 - 2 = 4 events left
        {
            let locked_log = log.inner.lock.read().unwrap();
            assert!(locked_log.head.is_some());
            assert_eq!(locked_log.num_events, calc_num_of_kept_events(6));
            assert_eq!(locked_log.oldest_height.0, 1);
        }
    }

    /// Test that we prune the event log once the maximum
    /// number of configured log entries has been reached.
    #[tokio::test]
    async fn test_log_prune_on_max_ents() {
        let (log, mut logger, sender) = new(Params {
            max_log_events: 9999,
            log_block_height_diff: 3,
        });

        let events = mock_tx_events("DEADBEEF");

        // the log can store up to 4 entries;
        // add batches of events to the log
        // split up across 4 log entries
        for height in 0..4 {
            sender
                .send_new_entry(LogEntry {
                    block_height: height.into(),
                    events: events.clone(),
                })
                .unwrap();
            logger.log_new_entry().await.unwrap();
        }

        // make sure these events landed in
        // the log, and that we didn't prune it
        {
            let locked_log = log.inner.lock.read().unwrap();
            assert!(locked_log.head.is_some());
            // `mock_tx_events` returns 2 events * 4 entries
            let num_events = 2 * 4;
            assert_eq!(locked_log.num_events, num_events);
            assert_eq!(locked_log.oldest_height.0, 0);
        }

        // add another entry to the log, for a total of 5 ents;
        // this should trigger a log prune
        sender
            .send_new_entry(LogEntry {
                block_height: 4.into(),
                events,
            })
            .unwrap();
        logger.log_new_entry().await.unwrap();

        // make sure we pruned the log
        {
            let locked_log = log.inner.lock.read().unwrap();
            assert!(locked_log.head.is_some());
            let num_events = calc_num_of_kept_ents(5) as usize * 2;
            assert_eq!(locked_log.num_events, num_events);
            assert_eq!(locked_log.oldest_height.0, 2);
        }
    }

    /// Test waiting for new log events.
    #[tokio::test]
    async fn test_snapshot_wait() {
        let (log, mut logger, sender) = new(Params::default());

        // wait up to 1s for events
        let max_wait_time = Duration::from_secs(1);

        let sender_task = tokio::spawn(async move {
            time::sleep(max_wait_time / 4).await;

            // send events to the logger
            sender
                .send_new_entry(LogEntry {
                    block_height: 0.into(),
                    events: mock_tx_events("DEADBEEF"),
                })
                .unwrap();
        });
        let logger_task = tokio::spawn(async move {
            logger.log_new_entry().await.unwrap();
        });

        // wait for new events to arrive
        let deadline = Instant::now() + max_wait_time;
        let snapshot = log.wait_snapshot(deadline).await.unwrap();
        assert_eq!(snapshot.num_events(), 2);

        // clean up tasks
        sender_task.await.unwrap();
        logger_task.await.unwrap();
    }
}
