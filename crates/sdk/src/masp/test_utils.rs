use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use namada_core::storage::{BlockHeight, IndexedTx};
use namada_state::LastBlock;
use tendermint_rpc::SimpleRequest;

use crate::error::Error;
use crate::io::Io;
use crate::masp::types::IndexedNoteEntry;
use crate::masp::utils::{
    CommitmentTreeUpdates, FetchQueueSender, IterProgress, MaspClient,
    PeekableIter, ProgressTracker,
};
use crate::masp::{ShieldedContext, ShieldedUtils};
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
    /// We sometimes want to iterate over values in the above
    /// channel more than once. Thus we need to resend them.
    send_masp_txs: flume::Sender<Option<IndexedNoteEntry>>,
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

#[cfg(any(test, feature = "async-client"))]
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
pub fn test_client(
    last_height: BlockHeight,
) -> (TestingClient, flume::Sender<Option<IndexedNoteEntry>>) {
    let (sender, recv) = flume::unbounded();
    let mut client = TestClient::new(RPC);
    client.state.in_mem_mut().last_block = Some(LastBlock {
        height: last_height,
        hash: Default::default(),
        time: Default::default(),
    });
    (
        TestingClient {
            inner: client,
            next_masp_txs: recv,
            send_masp_txs: sender.clone(),
        },
        sender,
    )
}

#[derive(Clone)]
pub struct TestingMaspClient<'a> {
    client: &'a TestingClient,
}

impl<'a> MaspClient<'a, TestingClient> for TestingMaspClient<'a> {
    fn new(client: &'a TestingClient) -> Self
    where
        Self: 'a,
    {
        Self { client }
    }

    async fn witness_map_updates<U: ShieldedUtils, IO: Io>(
        &self,
        _: &ShieldedContext<U>,
        _: &IO,
        _: IndexedTx,
        _: BlockHeight,
    ) -> Result<CommitmentTreeUpdates, Error> {
        let mut note_map_delta: BTreeMap<IndexedTx, usize> = Default::default();
        let mut channel_temp = vec![];
        let mut note_pos = 0;
        for msg in self.client.next_masp_txs.drain() {
            if let Some((ix, _)) = msg.as_ref() {
                note_map_delta.insert(*ix, note_pos);
                note_pos += 1;
            }
            channel_temp.push(msg);
        }
        for msg in channel_temp.drain(..) {
            self.client
                .send_masp_txs
                .send(msg)
                .map_err(|e| Error::Other(e.to_string()))?;
        }
        Ok(CommitmentTreeUpdates {
            commitment_tree: CommitmentTree::<Node>::empty(),
            witness_map: Default::default(),
            note_map_delta,
        })
    }

    async fn fetch_shielded_transfer<IO: Io>(
        &self,
        logger: &impl ProgressTracker<IO>,
        mut tx_sender: FetchQueueSender,
        from: u64,
        to: u64,
    ) -> Result<(), Error> {
        // N.B. this assumes one masp tx per block
        let mut fetch_iter = logger.fetch(from..=to);

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
            fetch_iter.next();
        }
        Ok(())
    }
}

/// An iterator that yields its first element
/// but runs forever on the second
/// `next` call.
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
