//! Helper functions and types

use std::collections::BTreeMap;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::memo::MemoBytes;
use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use masp_primitives::sapling::{Node, Note, PaymentAddress, ViewingKey};
use masp_primitives::transaction::Transaction;
use namada_core::collections::HashMap;
use namada_core::storage::{BlockHeight, TxIndex};
use namada_tx::{IndexedTx, IndexedTxRange, Tx};
#[cfg(not(target_family = "wasm"))]
use tokio::sync::Semaphore;

use crate::error::{Error, QueryError};
use crate::masp::{
    extract_masp_tx, extract_masp_tx_from_ibc_message,
    get_indexed_masp_events_at_height,
};
use crate::queries::Client;

#[cfg(not(target_family = "wasm"))]
const MAX_CONCURRENT_REQUESTS: usize = 100;

/// Type alias for convenience and profit
pub type IndexedNoteData = BTreeMap<IndexedTx, Vec<Transaction>>;

/// Type alias for the entries of [`IndexedNoteData`] iterators
pub type IndexedNoteEntry = (IndexedTx, Vec<Transaction>);

/// Borrowed version of an [`IndexedNoteEntry`]
pub type IndexedNoteEntryRefs<'a> = (&'a IndexedTx, &'a Vec<Transaction>);

/// Type alias for a successful note decryption.
pub type DecryptedData = (Note, PaymentAddress, MemoBytes);

/// Cache of decrypted notes.
#[derive(Default, BorshSerialize, BorshDeserialize)]
pub struct TrialDecrypted {
    inner:
        HashMap<IndexedTx, HashMap<ViewingKey, BTreeMap<usize, DecryptedData>>>,
}

impl TrialDecrypted {
    /// Get cached notes decrypted with `vk`, indexed at `itx`.
    pub fn get(
        &self,
        itx: &IndexedTx,
        vk: &ViewingKey,
    ) -> Option<&BTreeMap<usize, DecryptedData>> {
        self.inner.get(itx).and_then(|h| h.get(vk))
    }

    /// Take cached notes decrypted with `vk`, indexed at `itx`.
    pub fn take(
        &mut self,
        itx: &IndexedTx,
        vk: &ViewingKey,
    ) -> Option<BTreeMap<usize, DecryptedData>> {
        let (notes, no_more_notes) = {
            let viewing_keys_to_notes = self.inner.get_mut(itx)?;
            let notes = viewing_keys_to_notes.swap_remove(vk)?;
            (notes, viewing_keys_to_notes.is_empty())
        };
        if no_more_notes {
            self.inner.swap_remove(itx);
        }
        Some(notes)
    }

    /// Cache `notes` decrypted with `vk`, indexed at `itx`.
    pub fn insert(
        &mut self,
        itx: IndexedTx,
        vk: ViewingKey,
        notes: BTreeMap<usize, DecryptedData>,
    ) {
        self.inner.entry(itx).or_default().insert(vk, notes);
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// A cache of fetched indexed transactions.
///
/// An invariant that shielded-sync maintains is that
/// this cache either contains all transactions from
/// a given height, or none.
#[derive(Debug, Default, Clone, BorshSerialize, BorshDeserialize)]
pub struct Fetched {
    pub(crate) txs: IndexedNoteData,
}

impl Fetched {
    /// Append elements to the cache from an iterator.
    pub fn extend<I>(&mut self, items: I)
    where
        I: IntoIterator<Item = IndexedNoteEntry>,
    {
        self.txs.extend(items);
    }

    /// Iterates over the fetched transactions in the order
    /// they appear in blocks.
    pub fn iter(
        &self,
    ) -> impl IntoIterator<Item = IndexedNoteEntryRefs<'_>> + '_ {
        &self.txs
    }

    /// Iterates over the fetched transactions in the order
    /// they appear in blocks, whilst taking ownership of
    /// the returned data.
    pub fn take(&mut self) -> impl IntoIterator<Item = IndexedNoteEntry> {
        std::mem::take(&mut self.txs)
    }

    /// Add a single entry to the cache.
    pub fn insert(&mut self, (k, v): IndexedNoteEntry) {
        self.txs.insert(k, v);
    }

    /// Check if this cache has already been populated for a given
    /// block height.
    pub fn contains_height(&self, height: BlockHeight) -> bool {
        self.txs
            .range(IndexedTxRange::with_height(height))
            .next()
            .is_some()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Check the length of the fetched cache
    pub fn len(&self) -> usize {
        self.txs.len()
    }
}

impl IntoIterator for Fetched {
    type IntoIter = <IndexedNoteData as IntoIterator>::IntoIter;
    type Item = IndexedNoteEntry;

    fn into_iter(mut self) -> Self::IntoIter {
        let txs = std::mem::take(&mut self.txs);
        txs.into_iter()
    }
}

/// When retrying to fetch all notes in a
/// loop, this dictates the strategy for
/// how many attempts should be made.
#[derive(Copy, Clone)]
pub enum RetryStrategy {
    /// Always retry
    Forever,
    /// Limit number of retries to a fixed number
    Times(u64),
}

impl RetryStrategy {
    /// Check if retries are exhausted.
    pub fn may_retry(&mut self) -> bool {
        match self {
            RetryStrategy::Forever => true,
            RetryStrategy::Times(left) => {
                if *left == 0 {
                    false
                } else {
                    *left -= 1;
                    true
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
pub trait MaspClient: Clone {
    /// Return the last block height we can retrieve data from.
    #[allow(async_fn_in_trait)]
    async fn last_block_height(&self) -> Result<Option<BlockHeight>, Error>;

    /// Fetch shielded transfers from blocks heights in the range `[from, to]`,
    /// keeping track of progress through `progress`. The fetched transfers
    /// are sent over to a separate worker through `tx_sender`.
    #[allow(async_fn_in_trait)]
    async fn fetch_shielded_transfers(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Result<Vec<IndexedNoteEntry>, Error>;

    /// Return the capabilities of this client.
    fn capabilities(&self) -> MaspClientCapabilities;

    /// Fetch the commitment tree of height `height`.
    #[allow(async_fn_in_trait)]
    async fn fetch_commitment_tree(
        &self,
        height: BlockHeight,
    ) -> Result<CommitmentTree<Node>, Error>;

    /// Fetch the tx notes map of height `height`.
    #[allow(async_fn_in_trait)]
    async fn fetch_tx_notes_map(
        &self,
        height: BlockHeight,
    ) -> Result<BTreeMap<IndexedTx, usize>, Error>;

    /// Fetch the witness map of height `height`.
    #[allow(async_fn_in_trait)]
    async fn fetch_witness_map(
        &self,
        height: BlockHeight,
    ) -> Result<HashMap<usize, IncrementalWitness<Node>>, Error>;
}

#[cfg(not(target_family = "wasm"))]
struct LedgerMaspClientInner<C> {
    client: C,
    semaphore: Semaphore,
}

/// An inefficient MASP client which simply uses a
/// client to the blockchain to query it directly.
#[cfg(not(target_family = "wasm"))]
pub struct LedgerMaspClient<C> {
    inner: Arc<LedgerMaspClientInner<C>>,
}

#[cfg(not(target_family = "wasm"))]
impl<C> Clone for LedgerMaspClient<C> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl<C> LedgerMaspClient<C> {
    /// Create a new [`MaspClient`] given an rpc client.
    #[inline(always)]
    pub fn new(client: C) -> Self {
        Self {
            inner: Arc::new(LedgerMaspClientInner {
                client,
                semaphore: Semaphore::new(MAX_CONCURRENT_REQUESTS),
            }),
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl<C: Client + Send + Sync> MaspClient for LedgerMaspClient<C> {
    async fn last_block_height(&self) -> Result<Option<BlockHeight>, Error> {
        let maybe_block = crate::rpc::query_block(&self.inner.client).await?;
        Ok(maybe_block.map(|b| b.height))
    }

    async fn fetch_shielded_transfers(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Result<Vec<IndexedNoteEntry>, Error> {
        // Fetch all the transactions we do not have yet
        let mut txs = vec![];

        for height in from.0..=to.0 {
            let maybe_txs_results = async {
                let _permit = self.inner.semaphore.acquire().await.unwrap();

                get_indexed_masp_events_at_height(
                    &self.inner.client,
                    height.into(),
                    None,
                )
                .await
            };

            let txs_results = match maybe_txs_results.await? {
                Some(events) => events,
                None => {
                    continue;
                }
            };

            let block = {
                let _permit = self.inner.semaphore.acquire().await.unwrap();

                // Query the actual block to get the txs bytes. If we only need
                // one tx it might be slightly better to query
                // the /tx endpoint to reduce the amount of data
                // sent over the network, but this is a
                // minimal improvement and it's even hard to tell how many times
                // we'd need a single masp tx to make this worth it
                self.inner
                    .client
                    .block(height as u32)
                    .await
                    .map_err(|e| {
                        Error::from(QueryError::General(e.to_string()))
                    })?
                    .block
                    .data
            };

            for (idx, masp_sections_refs, ibc_tx_data_refs) in txs_results {
                let tx = Tx::try_from(block[idx.0 as usize].as_ref())
                    .map_err(|e| Error::Other(e.to_string()))?;
                let mut extracted_masp_txs = vec![];
                if let Some(masp_sections_refs) = masp_sections_refs {
                    extracted_masp_txs
                        .extend(extract_masp_tx(&tx, &masp_sections_refs)?);
                };
                if ibc_tx_data_refs.is_some() {
                    extracted_masp_txs
                        .extend(extract_masp_tx_from_ibc_message(&tx)?);
                }

                txs.push((
                    IndexedTx {
                        height: height.into(),
                        index: idx,
                    },
                    extracted_masp_txs,
                ));
            }
        }

        Ok(txs)
    }

    #[inline(always)]
    fn capabilities(&self) -> MaspClientCapabilities {
        MaspClientCapabilities::OnlyTransfers
    }

    async fn fetch_commitment_tree(
        &self,
        _: BlockHeight,
    ) -> Result<CommitmentTree<Node>, Error> {
        Err(Error::Other(
            "Commitment tree fetching is not implemented by this client"
                .to_string(),
        ))
    }

    async fn fetch_tx_notes_map(
        &self,
        _: BlockHeight,
    ) -> Result<BTreeMap<IndexedTx, usize>, Error> {
        Err(Error::Other(
            "Transaction notes map fetching is not implemented by this client"
                .to_string(),
        ))
    }

    async fn fetch_witness_map(
        &self,
        _: BlockHeight,
    ) -> Result<HashMap<usize, IncrementalWitness<Node>>, Error> {
        Err(Error::Other(
            "Witness map fetching is not implemented by this client"
                .to_string(),
        ))
    }
}

#[derive(Debug)]
#[cfg(not(target_family = "wasm"))]
struct IndexerMaspClientShared {
    semaphore: Semaphore,
    indexer_api: reqwest::Url,
    block_index: init_once::InitOnce<Option<xorf::BinaryFuse16>>,
}

/// MASP client implementation that queries data from the
/// [`namada-masp-indexer`].
///
/// [`namada-masp-indexer`]: <https://github.com/anoma/namada-masp-indexer>
#[cfg(not(target_family = "wasm"))]
#[derive(Clone, Debug)]
pub struct IndexerMaspClient {
    client: reqwest::Client,
    shared: Arc<IndexerMaspClientShared>,
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
    pub fn new(
        client: reqwest::Client,
        indexer_api: reqwest::Url,
        using_block_index: bool,
    ) -> Self {
        let shared = Arc::new(IndexerMaspClientShared {
            indexer_api,
            semaphore: Semaphore::new(MAX_CONCURRENT_REQUESTS),
            block_index: {
                let mut index = init_once::InitOnce::new();
                if !using_block_index {
                    index.init(|| None);
                }
                index
            },
        });
        Self { client, shared }
    }

    fn endpoint(&self, which: &str) -> String {
        format!("{}{which}", self.shared.indexer_api)
    }

    async fn get_server_error(
        response: reqwest::Response,
    ) -> Result<String, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Response {
            message: String,
        }

        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize server's error JSON response: {err}"
            ))
        })?;

        Ok(payload.message)
    }

    async fn last_block_index(&self) -> Result<xorf::BinaryFuse16, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Response {
            index: xorf::BinaryFuse16,
        }

        let _permit = self.shared.semaphore.acquire().await.unwrap();

        let response = self
            .client
            .get(self.endpoint("/block-index"))
            .keep_alive()
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch latest masp tx block index: {err}"
                ))
            })?;
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch latest masp tx block index: {err}"
            )));
        }
        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize latest masp tx block index JSON \
                 response: {err}"
            ))
        })?;

        Ok(payload.index)
    }
}

#[cfg(not(target_family = "wasm"))]
impl MaspClient for IndexerMaspClient {
    async fn last_block_height(&self) -> Result<Option<BlockHeight>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Response {
            block_height: u64,
        }

        let _permit = self.shared.semaphore.acquire().await.unwrap();

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
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch last block height: {err}"
            )));
        }
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

    async fn fetch_shielded_transfers(
        &self,
        BlockHeight(mut from): BlockHeight,
        BlockHeight(to): BlockHeight,
    ) -> Result<Vec<IndexedNoteEntry>, Error> {
        use serde::Deserialize;
        use xorf::Filter;

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
        let mut txs = vec![];

        let maybe_block_index = self
            .shared
            .block_index
            .try_init_async(async {
                let _permit = self.shared.semaphore.acquire().await.unwrap();
                self.last_block_index().await.ok()
            })
            .await
            .and_then(Option::as_ref);

        loop {
            'do_while: {
                let from_height = from;
                let off = (to - from).min(MAX_RANGE_THRES);
                let to_height = from + off;
                from += off;

                if let Some(block_index) = maybe_block_index {
                    let at_least_one_block_with_masp_txs = (from_height
                        ..=to_height)
                        .any(|height| block_index.contains(&height));

                    if !at_least_one_block_with_masp_txs {
                        // NB: skips code below, so it's more like a `continue`
                        break 'do_while;
                    }
                }

                let _permit = self.shared.semaphore.acquire().await.unwrap();

                let payload: TxResponse = {
                    let response = self
                        .client
                        .get(self.endpoint("/tx"))
                        .keep_alive()
                        .query(&[
                            ("height", from_height),
                            ("height_offset", off),
                        ])
                        .send()
                        .await
                        .map_err(|err| {
                            Error::Other(format!(
                                "Failed to fetch transactions in the height \
                                 range {from_height}-{to_height}: {err}"
                            ))
                        })?;
                    if !response.status().is_success() {
                        let err = Self::get_server_error(response).await?;
                        return Err(Error::Other(format!(
                            "Failed to fetch transactions in the range \
                             {from_height}-{to_height}: {err}"
                        )));
                    }
                    response.json().await.map_err(|err| {
                        Error::Other(format!(
                            "Could not deserialize the transactions JSON \
                             response in the height range \
                             {from_height}-{to_height}: {err}"
                        ))
                    })?
                };

                for Transaction {
                    batch,
                    block_index,
                    block_height,
                } in payload.txs
                {
                    let mut extracted_masp_txs =
                        Vec::with_capacity(batch.len());

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

                    txs.push((
                        IndexedTx {
                            height: BlockHeight(block_height),
                            index: TxIndex(block_index),
                        },
                        extracted_masp_txs,
                    ));
                }
            }

            if from >= to {
                break;
            }
        }

        Ok(txs)
    }

    #[inline(always)]
    fn capabilities(&self) -> MaspClientCapabilities {
        MaspClientCapabilities::AllData
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

        let _permit = self.shared.semaphore.acquire().await.unwrap();

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
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch commitment tree at height {height}: {err}"
            )));
        }
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
            // masp_tx_index: u64,
            note_position: usize,
            block_index: u32,
            block_height: u64,
        }

        #[derive(Deserialize)]
        struct Response {
            notes_map: Vec<Note>,
        }

        let _permit = self.shared.semaphore.acquire().await.unwrap();

        let response = self
            .client
            .get(self.endpoint("/notes-map"))
            .keep_alive()
            .query(&[("height", height)])
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch notes map at height {height}: {err}"
                ))
            })?;
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch notes map at height {height}: {err}"
            )));
        }
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

        let _permit = self.shared.semaphore.acquire().await.unwrap();

        let response = self
            .client
            .get(self.endpoint("/witness-map"))
            .keep_alive()
            .query(&[("height", height)])
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch witness map at height {height}: {err}"
                ))
            })?;
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch witness map at height {height}: {err}"
            )));
        }
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

/// Given a block height range we wish to request and a cache of fetched block
/// heights, returns the set of sub-ranges we need to request so that all blocks
/// in the inclusive range `[from, to]` get cached.
pub fn blocks_left_to_fetch(
    from: BlockHeight,
    to: BlockHeight,
    fetched: &Fetched,
) -> Vec<[BlockHeight; 2]> {
    const ZERO: BlockHeight = BlockHeight(0);

    if from > to {
        panic!("Empty range passed to `blocks_left_to_fetch`, [{from}, {to}]");
    }
    if from == ZERO || to == ZERO {
        panic!("Block height values start at 1");
    }

    let mut to_fetch = Vec::with_capacity((to.0 - from.0 + 1) as usize);
    let mut current_from = from;
    let mut need_to_fetch = true;

    for height in (from.0..=to.0).map(BlockHeight) {
        let height_in_cache = fetched.contains_height(height);

        // cross an upper gap boundary
        if need_to_fetch && height_in_cache {
            if height > current_from {
                to_fetch.push([
                    current_from,
                    height.checked_sub(1).expect("Height is greater than zero"),
                ]);
            }
            need_to_fetch = false;
        } else if !need_to_fetch && !height_in_cache {
            // cross a lower gap boundary
            current_from = height;
            need_to_fetch = true;
        }
    }
    if need_to_fetch {
        to_fetch.push([current_from, to]);
    }
    to_fetch
}

#[cfg(test)]
mod test_blocks_left_to_fetch {
    use proptest::prelude::*;

    use super::*;

    struct ArbRange {
        max_from: u64,
        max_len: u64,
    }

    impl Default for ArbRange {
        fn default() -> Self {
            Self {
                max_from: u64::MAX,
                max_len: 1000,
            }
        }
    }

    fn fetched_cache_with_blocks(
        blocks_in_cache: impl IntoIterator<Item = BlockHeight>,
    ) -> Fetched {
        let txs = blocks_in_cache
            .into_iter()
            .map(|height| {
                (
                    IndexedTx {
                        height,
                        index: TxIndex(0),
                    },
                    vec![],
                )
            })
            .collect();
        Fetched { txs }
    }

    fn blocks_in_range(
        from: BlockHeight,
        to: BlockHeight,
    ) -> impl Iterator<Item = BlockHeight> {
        (from.0..=to.0).map(BlockHeight)
    }

    prop_compose! {
        fn arb_block_range(ArbRange { max_from, max_len }: ArbRange)
        (
            from in 1u64..=max_from,
        )
        (
            from in Just(from),
            to in from..from.saturating_add(max_len)
        )
        -> (BlockHeight, BlockHeight)
        {
            (BlockHeight(from), BlockHeight(to))
        }
    }

    proptest! {
        #[test]
        fn test_empty_cache_with_singleton_output((from, to) in arb_block_range(ArbRange::default())) {
            let empty_cache = fetched_cache_with_blocks([]);

            let &[[returned_from, returned_to]] = blocks_left_to_fetch(
                from,
                to,
                &empty_cache,
            )
            .as_slice() else {
                return Err(TestCaseError::Fail("Test failed".into()));
            };

            prop_assert_eq!(returned_from, from);
            prop_assert_eq!(returned_to, to);
        }

        #[test]
        fn test_non_empty_cache_with_empty_output((from, to) in arb_block_range(ArbRange::default())) {
            let cache = fetched_cache_with_blocks(
                blocks_in_range(from, to)
            );

            let &[] = blocks_left_to_fetch(
                from,
                to,
                &cache,
            )
            .as_slice() else {
                return Err(TestCaseError::Fail("Test failed".into()));
            };
        }

        #[test]
        fn test_non_empty_cache_with_singleton_input_and_maybe_singleton_output(
            (from, to) in arb_block_range(ArbRange::default()),
            block_height in 1u64..1000,
        ) {
            test_non_empty_cache_with_singleton_input_and_maybe_singleton_output_inner(
                from,
                to,
                BlockHeight(block_height),
            )?;
        }

        #[test]
        fn test_non_empty_cache_with_singleton_hole_and_singleton_output(
            (first_from, first_to) in
                arb_block_range(ArbRange {
                    max_from: 1_000_000,
                    max_len: 1000,
                }),
        ) {
            // [from, to], [to + 2, 2 * to - from + 2]

            let hole = first_to + 1;
            let second_from = BlockHeight(first_to.0 + 2);
            let second_to = BlockHeight(2 * first_to.0 - first_from.0 + 2);

            let cache = fetched_cache_with_blocks(
                blocks_in_range(first_from, first_to)
                    .chain(blocks_in_range(second_from, second_to)),
            );

            let &[[returned_from, returned_to]] = blocks_left_to_fetch(
                first_from,
                second_to,
                &cache,
            )
            .as_slice() else {
                return Err(TestCaseError::Fail("Test failed".into()));
            };

            prop_assert_eq!(returned_from, hole);
            prop_assert_eq!(returned_to, hole);
        }
    }

    fn test_non_empty_cache_with_singleton_input_and_maybe_singleton_output_inner(
        from: BlockHeight,
        to: BlockHeight,
        block_height: BlockHeight,
    ) -> Result<(), TestCaseError> {
        let cache = fetched_cache_with_blocks(blocks_in_range(from, to));

        if block_height >= from && block_height <= to {
            // random height is inside the range of txs in cache

            let &[] = blocks_left_to_fetch(block_height, block_height, &cache)
                .as_slice()
            else {
                return Err(TestCaseError::Fail("Test failed".into()));
            };
        } else {
            // random height is outside the range of txs in cache

            let &[[returned_from, returned_to]] =
                blocks_left_to_fetch(block_height, block_height, &cache)
                    .as_slice()
            else {
                return Err(TestCaseError::Fail("Test failed".into()));
            };

            prop_assert_eq!(returned_from, block_height);
            prop_assert_eq!(returned_to, block_height);
        }

        Ok(())
    }

    #[test]
    fn test_happy_flow() {
        let cache = fetched_cache_with_blocks([
            BlockHeight(1),
            BlockHeight(5),
            BlockHeight(6),
            BlockHeight(8),
            BlockHeight(11),
        ]);

        let from = BlockHeight(1);
        let to = BlockHeight(10);

        let blocks_to_fetch = blocks_left_to_fetch(from, to, &cache);
        assert_eq!(
            &blocks_to_fetch,
            &[
                [BlockHeight(2), BlockHeight(4)],
                [BlockHeight(7), BlockHeight(7)],
                [BlockHeight(9), BlockHeight(10)],
            ],
        );
    }

    #[test]
    fn test_endpoint_cases() {
        let cache =
            fetched_cache_with_blocks(blocks_in_range(2.into(), 4.into()));
        let blocks_to_fetch = blocks_left_to_fetch(1.into(), 3.into(), &cache);
        assert_eq!(&blocks_to_fetch, &[[BlockHeight(1), BlockHeight(1)]]);

        // -------------

        let cache =
            fetched_cache_with_blocks(blocks_in_range(1.into(), 3.into()));
        let blocks_to_fetch = blocks_left_to_fetch(2.into(), 4.into(), &cache);
        assert_eq!(&blocks_to_fetch, &[[BlockHeight(4), BlockHeight(4)]]);

        // -------------

        let cache =
            fetched_cache_with_blocks(blocks_in_range(2.into(), 4.into()));
        let blocks_to_fetch = blocks_left_to_fetch(1.into(), 5.into(), &cache);
        assert_eq!(
            &blocks_to_fetch,
            &[
                [BlockHeight(1), BlockHeight(1)],
                [BlockHeight(5), BlockHeight(5)],
            ],
        );

        // -------------

        let cache =
            fetched_cache_with_blocks(blocks_in_range(1.into(), 5.into()));
        let blocks_to_fetch = blocks_left_to_fetch(2.into(), 4.into(), &cache);
        assert!(blocks_to_fetch.is_empty());
    }
}
