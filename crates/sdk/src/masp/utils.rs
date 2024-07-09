//! Helper functions and types

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap};
use std::sync::{Arc, Mutex};

use borsh::BorshDeserialize;
use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use masp_primitives::sapling::Node;
use namada_core::collections::HashMap;
use namada_core::storage::{BlockHeight, TxIndex};
use namada_tx::{IndexedTx, Tx};

use crate::control_flow::ShutdownSignal;
use crate::error::{Error, QueryError};
use crate::io::Io;
use crate::masp::{
    extract_masp_tx, get_indexed_masp_events_at_height, IndexedNoteEntry,
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

impl MaspClientCapabilities {
    /// Check if the lack of one or more capabilities in the
    /// masp client implementation warrants a manual update
    /// of the witnesses map.
    pub const fn needs_witness_map_update(&self) -> bool {
        matches!(self, Self::OnlyTransfers)
    }

    /// Check if the masp client is able to fetch a pre-built
    /// commitment tree.
    pub const fn may_fetch_pre_built_tree(&self) -> bool {
        matches!(self, Self::AllData)
    }

    /// Check if the masp client is able to fetch a pre-built
    /// notes map.
    pub const fn may_fetch_pre_built_notes_map(&self) -> bool {
        matches!(self, Self::AllData)
    }

    /// Check if the masp client is able to fetch a pre-built
    /// witness map.
    pub const fn may_fetch_pre_built_witness_map(&self) -> bool {
        matches!(self, Self::AllData)
    }
}

/// This abstracts away the implementation details
/// of how shielded-sync fetches the necessary data
/// from a remote server.
// TODO: redesign this api with progress bars in mind
pub trait MaspClient {
    /// Return the last block height we can retrieve data from.
    #[allow(async_fn_in_trait)]
    async fn last_block_height(&self) -> Result<Option<BlockHeight>, Error>;

    /// Fetch shielded transfers from blocks heights in the range `[from, to]`,
    /// keeping track of progress through `progress`. The fetched transfers
    /// are sent over to a separate worker through `tx_sender`.
    #[allow(async_fn_in_trait)]
    async fn fetch_shielded_transfers<IO: Io>(
        &self,
        progress: &impl ProgressTracker<IO>,
        shutdown_signal: &mut ShutdownSignal,
        tx_sender: flume::Sender<Range>,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Result<(), Error>;

    /// Return the capabilities of this client.
    #[inline(always)]
    fn capabilities(&self) -> MaspClientCapabilities {
        MaspClientCapabilities::OnlyTransfers
    }

    /// Fetch the commitment tree of height `height`.
    #[allow(async_fn_in_trait)]
    async fn fetch_commitment_tree(
        &self,
        height: BlockHeight,
    ) -> Result<CommitmentTree<Node>, Error> {
        _ = height;
        Err(Error::Other(
            "Commitment tree fetching is not implemented by this client"
                .to_string(),
        ))
    }

    /// Fetch the tx notes map of height `height`.
    #[allow(async_fn_in_trait)]
    async fn fetch_tx_notes_map(
        &self,
        height: BlockHeight,
    ) -> Result<BTreeMap<IndexedTx, usize>, Error> {
        _ = height;
        Err(Error::Other(
            "Transaction notes map fetching is not implemented by this client"
                .to_string(),
        ))
    }

    /// Fetch the witness map of height `height`.
    #[allow(async_fn_in_trait)]
    async fn fetch_witness_map(
        &self,
        height: BlockHeight,
    ) -> Result<HashMap<usize, IncrementalWitness<Node>>, Error> {
        _ = height;
        Err(Error::Other(
            "Witness map fetching is not implemented by this client"
                .to_string(),
        ))
    }
}

/// An inefficient MASP client which simply uses a
/// client to the blockchain to query it directly.
#[cfg(not(target_family = "wasm"))]
#[derive(Clone)]
pub struct LedgerMaspClient<'client, C> {
    client: &'client C,
}

#[cfg(not(target_family = "wasm"))]
impl<'client, C> LedgerMaspClient<'client, C> {
    /// Create a new [`MaspClient`] given an rpc client.
    pub const fn new(client: &'client C) -> Self {
        Self { client }
    }
}

#[cfg(not(target_family = "wasm"))]
impl<C: Client + Sync> MaspClient for LedgerMaspClient<'_, C> {
    async fn last_block_height(&self) -> Result<Option<BlockHeight>, Error> {
        let maybe_block = crate::rpc::query_block(self.client).await?;
        Ok(maybe_block.map(|b| b.height))
    }

    async fn fetch_shielded_transfers<IO: Io>(
        &self,
        progress: &impl ProgressTracker<IO>,
        shutdown_signal: &mut ShutdownSignal,
        mut tx_sender: flume::Sender<Range>,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Result<(), Error> {
        // Fetch all the transactions we do not have yet
        let mut fetch_iter = progress.fetch(from.0..=to.0);
        let mut range = Range {
            from,
            to,
            txs: vec![],
        };
        loop {
            let Some(height) = fetch_iter.peek().copied() else {
                break;
            };
            _ = fetch_iter.next();

            if shutdown_signal.received() {
                return Err(Error::Interrupt(
                    "[ShieldedSync::Fetching]".to_string(),
                ));
            }

            // TODO: Fix
            // if tx_sender.contains_height(height) {
            //     continue;
            // }

            let txs_results = match get_indexed_masp_events_at_height(
                self.client,
                height.into(),
                None,
            )
            .await?
            {
                Some(events) => events,
                None => {
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
                range.txs.push((
                    IndexedTx {
                        height: height.into(),
                        index: idx,
                    },
                    extracted_masp_txs,
                ));
            }
        }
        tx_sender.send(range).unwrap();

        Ok(())
    }
}

/// MASP client implementation that queries data from the
/// [`namada-masp-indexer`].
///
/// [`namada-masp-indexer`]: <https://github.com/anoma/namada-masp-indexer>
#[cfg(not(target_family = "wasm"))]
#[derive(Clone, Debug)]
pub struct IndexerMaspClient {
    indexer_api: Arc<reqwest::Url>,
    client: reqwest::Client,
}

#[cfg(not(target_family = "wasm"))]
trait RequestBuilderExt {
    fn keep_alive(self) -> reqwest::RequestBuilder;
}

#[cfg(not(target_family = "wasm"))]
impl RequestBuilderExt for reqwest::RequestBuilder {
    #[inline(always)]
    fn keep_alive(self) -> reqwest::RequestBuilder {
        self.header("Connection", "Keep-Alive")
    }
}

#[cfg(not(target_family = "wasm"))]
impl IndexerMaspClient {
    /// Create a new [`IndexerMaspClient`].
    #[inline]
    pub fn new(client: reqwest::Client, indexer_api: reqwest::Url) -> Self {
        let indexer_api = Arc::new(indexer_api);
        Self {
            client,
            indexer_api,
        }
    }

    fn endpoint(&self, which: &str) -> String {
        format!("{}{which}", self.indexer_api)
    }
}

#[cfg(not(target_family = "wasm"))]
impl MaspClient for IndexerMaspClient {
    #[inline(always)]
    fn capabilities(&self) -> MaspClientCapabilities {
        MaspClientCapabilities::AllData
    }

    async fn last_block_height(&self) -> Result<Option<BlockHeight>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Response {
            block_height: u64,
        }

        let response = self
            .client
            .get(self.endpoint("/height"))
            .keep_alive()
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch latest block height: {err}"
                ))
            })?;
        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize latest block height JSON response: \
                 {err}"
            ))
        })?;

        Ok(if payload.block_height != 0 {
            Some(BlockHeight(payload.block_height))
        } else {
            None
        })
    }

    async fn fetch_shielded_transfers<IO: Io>(
        &self,
        progress: &impl ProgressTracker<IO>,
        shutdown_signal: &mut ShutdownSignal,
        mut tx_sender: flume::Sender<Range>,
        BlockHeight(mut from): BlockHeight,
        BlockHeight(to): BlockHeight,
    ) -> Result<(), Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct TransactionSlot {
            // masp_tx_index: u64,
            bytes: Vec<u8>,
        }

        #[derive(Deserialize)]
        struct Transaction {
            batch: Vec<TransactionSlot>,
            block_index: u32,
            block_height: u64,
        }

        #[derive(Deserialize)]
        struct TxResponse {
            txs: Vec<Transaction>,
        }

        if from > to {
            return Err(Error::Other(format!(
                "Invalid block range {from}-{to}: Beginning height {from} is \
                 greater than ending height {to}"
            )));
        }

        const MAX_RANGE_THRES: u64 = 30;
        let mut fetch_iter = progress.fetch(from..=to);
        let mut range = Range {
            from: BlockHeight(from),
            to: BlockHeight(to),
            txs: vec![],
        };

        loop {
            let from_height = from;
            let off = (to - from).min(MAX_RANGE_THRES);
            let to_height = from + off;
            from += off;

            let txs_fut = async {
                let response = self
                    .client
                    .get(self.endpoint("/tx"))
                    .query(&[("height", from_height), ("height_offset", off)])
                    .send()
                    .await
                    .map_err(|err| {
                        Error::Other(format!(
                            "Failed to fetch transactions in the height range \
                             {from_height}-{to_height}: {err}"
                        ))
                    })?;
                let payload: TxResponse =
                    response.json().await.map_err(|err| {
                        Error::Other(format!(
                            "Could not deserialize the transactions JSON \
                             response in the height range \
                             {from_height}-{to_height}: {err}"
                        ))
                    })?;

                Ok::<_, Error>(payload)
            };
            let payload = tokio::select! {
                maybe_payload = txs_fut => {
                    maybe_payload?
                }
                _ = &mut *shutdown_signal => {
                    return Err(Error::Interrupt(
                        "[ShieldedSync::Fetching]".to_string(),
                    ));
                }
            };

            let mut last_height = None;

            for Transaction {
                batch,
                block_index,
                block_height,
            } in payload.txs
            {
                let mut extracted_masp_txs = Vec::with_capacity(batch.len());

                for TransactionSlot { bytes } in batch {
                    type MaspTx = masp_primitives::transaction::Transaction;

                    extracted_masp_txs.push(
                        MaspTx::try_from_slice(&bytes).map_err(|err| {
                            Error::Other(format!(
                                "Could not deserialize the masp txs borsh \
                                 data at height {block_height} and index \
                                 {block_index}: {err}"
                            ))
                        })?,
                    );
                }

                range.txs.push((
                    IndexedTx {
                        height: BlockHeight(block_height),
                        index: TxIndex(block_index),
                    },
                    extracted_masp_txs,
                ));

                let curr_height = Some(block_height);
                if curr_height > last_height {
                    last_height = curr_height;
                    _ = fetch_iter.next();
                }
            }

            if from >= to {
                break;
            }
        }

        // NB: a hack to drain the iterator in case
        // there were still some items left
        // TODO: improve this lol
        while fetch_iter.next().is_some() {}
        tx_sender.send(range).unwrap();
        Ok(())
    }

    async fn fetch_commitment_tree(
        &self,
        BlockHeight(height): BlockHeight,
    ) -> Result<CommitmentTree<Node>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Response {
            commitment_tree: Vec<u8>,
        }

        let response = self
            .client
            .get(self.endpoint("/commitment-tree"))
            .keep_alive()
            .query(&[("height", height)])
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch commitment tree at height {height}: {err}"
                ))
            })?;
        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize the commitment tree JSON response at \
                 height {height}: {err}"
            ))
        })?;

        BorshDeserialize::try_from_slice(&payload.commitment_tree).map_err(
            |err| {
                Error::Other(format!(
                    "Could not deserialize the commitment tree borsh data at \
                     height {height}: {err}"
                ))
            },
        )
    }

    async fn fetch_tx_notes_map(
        &self,
        BlockHeight(height): BlockHeight,
    ) -> Result<BTreeMap<IndexedTx, usize>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Note {
            // is_fee_unshielding: bool,
            // masp_tx_index: u64,
            note_position: usize,
            block_index: u32,
            block_height: u64,
        }

        #[derive(Deserialize)]
        struct Response {
            notes_map: Vec<Note>,
        }

        let response = self
            .client
            .get(self.endpoint("/notes-map"))
            .query(&[("height", height)])
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch notes map at height {height}: {err}"
                ))
            })?;
        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize the notes map JSON response at height \
                 {height}: {err}"
            ))
        })?;

        Ok(payload
            .notes_map
            .into_iter()
            .map(
                |Note {
                     block_index,
                     block_height,
                     note_position,
                 }| {
                    (
                        IndexedTx {
                            index: TxIndex(block_index),
                            height: BlockHeight(block_height),
                        },
                        note_position,
                    )
                },
            )
            .collect())
    }

    async fn fetch_witness_map(
        &self,
        BlockHeight(height): BlockHeight,
    ) -> Result<HashMap<usize, IncrementalWitness<Node>>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Witness {
            bytes: Vec<u8>,
            index: usize,
        }

        #[derive(Deserialize)]
        struct WitnessMapResponse {
            witnesses: Vec<Witness>,
        }

        let response = self
            .client
            .get(self.endpoint("/witness-map"))
            .query(&[("height", height)])
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch witness map at height {height}: {err}"
                ))
            })?;
        let payload: WitnessMapResponse =
            response.json().await.map_err(|err| {
                Error::Other(format!(
                    "Could not deserialize the witness map JSON response at \
                     height {height}: {err}"
                ))
            })?;

        payload.witnesses.into_iter().try_fold(
            HashMap::new(),
            |mut accum, Witness { index, bytes }| {
                let witness = BorshDeserialize::try_from_slice(&bytes)
                    .map_err(|err| {
                        Error::Other(format!(
                            "Could not deserialize the witness borsh data at \
                             height {height}: {err}"
                        ))
                    })?;
                accum.insert(index, witness);
                Ok(accum)
            },
        )
    }
}

pub struct Range {
    from: BlockHeight,
    to: BlockHeight,
    txs: Vec<IndexedNoteEntry>,
}

impl PartialEq<Self> for Range {
    fn eq(&self, other: &Self) -> bool {
        (self.from, self.to).eq(&(other.from, other.to))
    }
}

impl PartialOrd for Range {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        (other.from, other.to).partial_cmp(&(self.from, self.to))
    }
}
pub struct FetchedTxs {
    heap: BinaryHeap<Range>,
    curr_block_height: BlockHeight,
}

impl FetchedTxs {
    fn next(&mut self) -> Option<Range> {
        let maybe_next = self.heap.peek()?;

        if maybe_next.from == self.curr_block_height {
            self.curr_block_height = maybe_next.to + 1;
            self.heap.pop()
        } else {
            None
        }
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
    use std::collections::VecDeque;

    use namada_core::storage::TxIndex;
    use namada_tx::IndexedTx;

    use crate::masp::test_utils::arbitrary_masp_tx;
    use crate::masp::utils::RetryStrategy;
    use crate::masp::IndexedNoteEntry;

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
