use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use masp_primitives::sapling::Node;
use namada_core::collections::HashMap;
use namada_core::storage::BlockHeight;
use namada_state::LastBlock;
use namada_tx::IndexedTx;
use tendermint_rpc::SimpleRequest;

use crate::control_flow::ShutdownSignal;
use crate::error::Error;
use crate::io::Io;
use crate::masp::utils::{
    FetchQueueSender, IterProgress, MaspClient, MaspClientCapabilities,
    PeekableIter, ProgressTracker,
};
use crate::masp::IndexedNoteEntry;
use crate::queries::testing::TestClient;
use crate::queries::{Client, EncodedResponseQuery, Rpc, RPC};

/// A client for testing the shielded-sync functionality
pub struct TestingClient {
    /// An actual mocked client for querying
    inner: TestClient<Rpc>,
    /// Used to inject a channel that we control into
    /// the fetch algorithm. The option is to mock connection
    /// failures.
    next_masp_txs: flume::Receiver<Option<IndexedNoteEntry>>,
}

impl Deref for TestingClient {
    type Target = TestClient<Rpc>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TestingClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
impl Client for TestingClient {
    type Error = std::io::Error;

    async fn request(
        &self,
        path: String,
        data: Option<Vec<u8>>,
        height: Option<BlockHeight>,
        prove: bool,
    ) -> Result<EncodedResponseQuery, Self::Error> {
        self.inner.request(path, data, height, prove).await
    }

    async fn perform<R>(
        &self,
        request: R,
    ) -> Result<R::Output, tendermint_rpc::Error>
    where
        R: SimpleRequest,
    {
        self.inner.perform(request).await
    }
}

/// Creat a test client for unit testing as well
/// as a channel for communicating with it.
pub fn test_client(
    last_height: BlockHeight,
) -> (TestingClient, flume::Sender<Option<IndexedNoteEntry>>) {
    let (sender, recv) = flume::unbounded();
    let mut client = TestClient::new(RPC);
    client.state.in_mem_mut().last_block = Some(LastBlock {
        height: last_height,
        time: Default::default(),
    });
    (
        TestingClient {
            inner: client,
            next_masp_txs: recv,
        },
        sender,
    )
}

/// A client for unit tests. It "fetches" a new note
/// when a channel controlled by the unit test sends
/// it one.
#[derive(Clone)]
pub struct TestingMaspClient<'a> {
    client: &'a TestingClient,
}

impl<'client> TestingMaspClient<'client> {
    /// Create a new [`TestingMaspClient`] given an rpc client
    /// [`TestingClient`].
    pub const fn new(client: &'client TestingClient) -> Self {
        Self { client }
    }
}

impl MaspClient for TestingMaspClient<'_> {
    async fn last_block_height(&self) -> Result<Option<BlockHeight>, Error> {
        Ok(self
            .client
            .state
            .in_mem()
            .last_block
            .as_ref()
            .map(|b| b.height))
    }

    async fn fetch_shielded_transfers<IO: Io>(
        &self,
        progress: &impl ProgressTracker<IO>,
        shutdown_signal: &mut ShutdownSignal,
        mut tx_sender: FetchQueueSender,
        BlockHeight(from): BlockHeight,
        BlockHeight(to): BlockHeight,
    ) -> Result<(), Error> {
        // N.B. this assumes one masp tx per block
        let mut fetch_iter = progress.fetch(from..=to);

        while fetch_iter.peek().is_some() {
            let next_tx = self
                .client
                .next_masp_txs
                .recv()
                .expect("Test failed")
                .ok_or_else(|| {
                    Error::Other(
                        "Connection to fetch MASP txs failed".to_string(),
                    )
                })?;
            tx_sender.send(next_tx);
            if shutdown_signal.received() {
                return Err(Error::Interrupt("[Testing::Fetch]".to_string()));
            }
            fetch_iter.next();
        }
        Ok(())
    }

    #[inline(always)]
    fn capabilities(&self) -> MaspClientCapabilities {
        MaspClientCapabilities::OnlyTransfers
    }

    async fn fetch_commitment_tree(
        &self,
        _: BlockHeight,
    ) -> Result<CommitmentTree<Node>, Error> {
        unimplemented!(
            "Commitment tree fetching is not implemented by this client"
        )
    }

    async fn fetch_tx_notes_map(
        &self,
        _: BlockHeight,
    ) -> Result<BTreeMap<IndexedTx, usize>, Error> {
        unimplemented!(
            "Transaction notes map fetching is not implemented by this client"
        )
    }

    async fn fetch_witness_map(
        &self,
        _: BlockHeight,
    ) -> Result<HashMap<usize, IncrementalWitness<Node>>, Error> {
        unimplemented!("Witness map fetching is not implemented by this client")
    }
}

/// An iterator that yields its first element only
struct YieldOnceIterator {
    first: Option<IndexedNoteEntry>,
}

impl YieldOnceIterator {
    fn new<T>(mut iter: T) -> Self
    where
        T: Iterator<Item = IndexedNoteEntry>,
    {
        let first = iter.next();
        Self { first }
    }
}

impl Iterator for YieldOnceIterator {
    type Item = IndexedNoteEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.first.take()
    }
}

/// A progress tracker that only scans the first fetched
/// block. The rest are left in the unscanned cache
/// for the purposes of testing the persistence of
/// this cache.
pub(super) struct TestUnscannedTracker<'io, IO> {
    io: &'io IO,
    progress: Arc<Mutex<IterProgress>>,
}

impl<'io, IO: Io> TestUnscannedTracker<'io, IO> {
    pub fn new(io: &'io IO) -> Self {
        Self {
            io,
            progress: Arc::new(Mutex::new(Default::default())),
        }
    }
}

impl<'io, IO: Io> ProgressTracker<IO> for TestUnscannedTracker<'io, IO> {
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
        crate::masp::utils::DefaultFetchIterator {
            inner: items,
            progress: self.progress.clone(),
            peeked: None,
        }
    }

    fn scan<I>(&self, items: I) -> impl Iterator<Item = IndexedNoteEntry> + Send
    where
        I: Iterator<Item = IndexedNoteEntry> + Send,
    {
        YieldOnceIterator::new(items)
    }

    fn left_to_fetch(&self) -> usize {
        let locked = self.progress.lock().unwrap();
        locked.length - locked.index
    }
}
