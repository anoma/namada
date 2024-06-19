//! Helper functions and types

use std::sync::{Arc, Mutex};

use namada_core::storage::BlockHeight;
use namada_tx::{IndexedTx, Tx};

use crate::control_flow::ShutdownSignal;
use crate::error::{Error, QueryError};
use crate::io::Io;
use crate::masp::{
    extract_masp_tx, get_indexed_masp_events_at_height, IndexedNoteEntry,
    Unscanned,
};
use crate::queries::Client;

/// When retrying to fetch all notes in a
/// loop, this dictates the strategy for
/// how many attempts should be made.
pub enum RetryStrategy {
    /// Always retry
    Forever,
    /// Limit number of retries to a fixed number
    Times(u64),
}

impl Iterator for RetryStrategy {
    type Item = ();

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Forever => Some(()),
            Self::Times(count) => {
                if *count == 0 {
                    None
                } else {
                    *count -= 1;
                    Some(())
                }
            }
        }
    }
}

/// Enumerates the capabilities of a [`MaspClient`] implementation.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum MaspClientCapabilities {
    /// The masp client implementation is only capable of fetching shielded
    /// transfers.
    OnlyTransfers,
    /// The masp client implementation is capable of not only fetching shielded
    /// transfers, but also of fetching commitment trees, witness maps, and
    /// note maps.
    AllData,
}

/// This abstracts away the implementation details
/// of how shielded-sync fetches the necessary data
/// from a remote server.
pub trait MaspClient<'client, C: Client> {
    /// Return the wrapped client.
    fn rpc_client(&self) -> &C;

    /// Return the capabilities of this client.
    fn capabilities(&self) -> MaspClientCapabilities;

    /// Fetch shielded transfers from blocks heights in the range `[from, to]`,
    /// keeping track of progress through `progress`. The fetched transfers
    /// are sent over to a separate worker through `tx_sender`.
    #[allow(async_fn_in_trait)]
    async fn fetch_shielded_transfers<IO: Io>(
        &self,
        progress: &impl ProgressTracker<IO>,
        shutdown_signal: &mut ShutdownSignal,
        tx_sender: FetchQueueSender,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Result<(), Error>;
}

/// An inefficient MASP client which simply uses a
/// client to the blockchain to query it directly.
pub struct LedgerMaspClient<'client, C> {
    client: &'client C,
}

impl<'client, C> LedgerMaspClient<'client, C> {
    /// Create a new [`MaspClient`] given an rpc client.
    pub const fn new(client: &'client C) -> Self {
        Self { client }
    }
}

#[cfg(not(target_family = "wasm"))]
impl<'client, C: Client + Sync> MaspClient<'client, C>
    for LedgerMaspClient<'client, C>
where
    LedgerMaspClient<'client, C>: 'client,
{
    fn rpc_client(&self) -> &C {
        self.client
    }

    fn capabilities(&self) -> MaspClientCapabilities {
        MaspClientCapabilities::OnlyTransfers
    }

    async fn fetch_shielded_transfers<IO: Io>(
        &self,
        progress: &impl ProgressTracker<IO>,
        shutdown_signal: &mut ShutdownSignal,
        mut tx_sender: FetchQueueSender,
        BlockHeight(from): BlockHeight,
        BlockHeight(to): BlockHeight,
    ) -> Result<(), Error> {
        // Fetch all the transactions we do not have yet
        let mut fetch_iter = progress.fetch(from..=to);

        while let Some(height) = fetch_iter.peek() {
            if shutdown_signal.received() {
                return Err(Error::Interrupt(
                    "[ShieldedSync::Fetching]".to_string(),
                ));
            }
            let height = *height;
            if tx_sender.contains_height(height) {
                fetch_iter.next();
                continue;
            }

            let txs_results = match get_indexed_masp_events_at_height(
                self.client,
                height.into(),
                None,
            )
            .await?
            {
                Some(events) => events,
                None => {
                    fetch_iter.next();
                    continue;
                }
            };

            // Query the actual block to get the txs bytes. If we only need one
            // tx it might be slightly better to query the /tx endpoint to
            // reduce the amount of data sent over the network, but this is a
            // minimal improvement and it's even hard to tell how many times
            // we'd need a single masp tx to make this worth it
            let block = self
                .client
                .block(height as u32)
                .await
                .map_err(|e| Error::from(QueryError::General(e.to_string())))?
                .block
                .data;

            for (idx, masp_sections_refs) in txs_results {
                let tx = Tx::try_from(block[idx.0 as usize].as_ref())
                    .map_err(|e| Error::Other(e.to_string()))?;
                let extracted_masp_txs =
                    extract_masp_tx(&tx, &masp_sections_refs).await?;

                tx_sender.send((
                    IndexedTx {
                        height: height.into(),
                        index: idx,
                    },
                    extracted_masp_txs,
                ));
            }
            fetch_iter.next();
        }

        Ok(())
    }
}

/// A channel-like struct for "sending" newly fetched blocks
/// to the scanning algorithm.
///
/// Holds a pointer to the unscanned cache which it can append to.
/// Furthermore, has an actual channel for keeping track if
/// 1. The process in possession of the channel is still alive
/// 2. Quickly updating the latest block height scanned.
#[derive(Clone)]
pub struct FetchQueueSender {
    cache: Unscanned,
    last_fetched: flume::Sender<BlockHeight>,
}

/// A channel-like struct for "receiving" new fetched
/// blocks for the scanning algorithm.
///
/// This is implemented as an iterator for the scanning
/// algorithm. This receiver pulls from the cache until
/// it is empty. It then waits until new entries appear
/// in the cache or the sender hangs up.
#[derive(Clone)]
pub(super) struct FetchQueueReceiver {
    cache: Unscanned,
    last_fetched: flume::Receiver<BlockHeight>,
}

impl FetchQueueReceiver {
    /// Check if the sender has hung up.
    fn sender_alive(&self) -> bool {
        self.last_fetched.sender_count() > 0
    }
}

impl Iterator for FetchQueueReceiver {
    type Item = IndexedNoteEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(entry) = self.cache.pop_first() {
            Some(entry)
        } else {
            while self.sender_alive() {
                if let Some(entry) = self.cache.pop_first() {
                    return Some(entry);
                }
            }
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.last_fetched.len();
        (size, Some(size))
    }
}

impl FetchQueueSender {
    /// Checks if the channel is already populated for the given block height
    pub(super) fn contains_height(&self, height: u64) -> bool {
        self.cache.contains_height(height)
    }

    /// Send a new value of the channel
    pub(super) fn send(&mut self, data: IndexedNoteEntry) {
        self.last_fetched.send(data.0.height).unwrap();
        self.cache.insert(data);
    }
}

/// A convenience for creating a channel for fetching blocks.
pub mod fetch_channel {

    use super::{FetchQueueReceiver, FetchQueueSender, Unscanned};
    pub(in super::super) fn new(
        cache: Unscanned,
    ) -> (FetchQueueSender, FetchQueueReceiver) {
        let (fetch_send, fetch_recv) = flume::unbounded();
        (
            FetchQueueSender {
                cache: cache.clone(),
                last_fetched: fetch_send,
            },
            FetchQueueReceiver {
                cache: cache.clone(),
                last_fetched: fetch_recv,
            },
        )
    }
}

/// An enum to indicate how to track progress depending on
/// whether sync is currently fetch or scanning blocks.
#[derive(Debug, Copy, Clone)]
pub enum ProgressType {
    /// Fetch
    Fetch,
    /// Scan
    Scan,
}

/// A peekable iterator interface
pub trait PeekableIter<I> {
    /// Peek at next element
    fn peek(&mut self) -> Option<&I>;

    /// get next element
    fn next(&mut self) -> Option<I>;
}

impl<I, J> PeekableIter<J> for std::iter::Peekable<I>
where
    I: Iterator<Item = J>,
{
    fn peek(&mut self) -> Option<&J> {
        self.peek()
    }

    fn next(&mut self) -> Option<J> {
        <Self as Iterator>::next(self)
    }
}

/// This trait keeps track of how much progress the
/// shielded sync algorithm has made relative to the inputs.
///
/// It should track how much has been fetched and scanned and
/// whether the fetching has been finished.
///
/// Additionally, it has access to IO in case the struct implementing
/// this trait wishes to log this progress.
pub trait ProgressTracker<IO: Io> {
    /// Get an IO handle
    fn io(&self) -> &IO;

    /// Return an iterator to fetched shielded transfers
    fn fetch<I>(&self, items: I) -> impl PeekableIter<u64>
    where
        I: Iterator<Item = u64>;

    /// Return an iterator over MASP transactions to be scanned
    fn scan<I>(
        &self,
        items: I,
    ) -> impl Iterator<Item = IndexedNoteEntry> + Send
    where
        I: Iterator<Item = IndexedNoteEntry> + Send;

    /// The number of blocks that need to be fetched
    fn left_to_fetch(&self) -> usize;
}

/// The default type for tracking the progress of shielded-sync.
#[derive(Debug, Clone)]
pub struct DefaultTracker<'io, IO: Io> {
    io: &'io IO,
    progress: Arc<Mutex<IterProgress>>,
}

impl<'io, IO: Io> DefaultTracker<'io, IO> {
    /// New [`DefaultTracker`]
    pub fn new(io: &'io IO) -> Self {
        Self {
            io,
            progress: Arc::new(Mutex::new(Default::default())),
        }
    }
}

#[derive(Default, Copy, Clone, Debug)]
pub(super) struct IterProgress {
    pub index: usize,
    pub length: usize,
}

pub(super) struct DefaultFetchIterator<I>
where
    I: Iterator<Item = u64>,
{
    pub inner: I,
    pub progress: Arc<Mutex<IterProgress>>,
    pub peeked: Option<u64>,
}

impl<I> PeekableIter<u64> for DefaultFetchIterator<I>
where
    I: Iterator<Item = u64>,
{
    fn peek(&mut self) -> Option<&u64> {
        if self.peeked.is_none() {
            self.peeked = self.inner.next();
        }
        self.peeked.as_ref()
    }

    fn next(&mut self) -> Option<u64> {
        self.peek();
        let item = self.peeked.take()?;
        let mut locked = self.progress.lock().unwrap();
        locked.index += 1;
        Some(item)
    }
}

impl<'io, IO: Io> ProgressTracker<IO> for DefaultTracker<'io, IO> {
    fn io(&self) -> &IO {
        self.io
    }

    fn fetch<I>(&self, items: I) -> impl PeekableIter<u64>
    where
        I: Iterator<Item = u64>,
    {
        {
            let mut locked = self.progress.lock().unwrap();
            locked.length = items.size_hint().0;
        }
        DefaultFetchIterator {
            inner: items,
            progress: self.progress.clone(),
            peeked: None,
        }
    }

    fn scan<I>(&self, items: I) -> impl Iterator<Item = IndexedNoteEntry> + Send
    where
        I: IntoIterator<Item = IndexedNoteEntry>,
    {
        let items: Vec<_> = items.into_iter().collect();
        items.into_iter()
    }

    fn left_to_fetch(&self) -> usize {
        let locked = self.progress.lock().unwrap();
        locked.length - locked.index
    }
}

#[cfg(test)]
mod util_tests {
    use crate::masp::utils::RetryStrategy;

    #[test]
    fn test_retry_strategy() {
        let strategy = RetryStrategy::Times(3);
        let mut counter = 0;
        for _ in strategy {
            counter += 1;
        }
        assert_eq!(counter, 3);
    }
}
