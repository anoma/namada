use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

use borsh::BorshDeserialize;
use masp_primitives::transaction::Transaction;
use namada_core::storage::BlockHeight;
use namada_state::LastBlock;
use tendermint_rpc::SimpleRequest;

use crate::control_flow::ShutdownSignal;
use crate::error::Error;
use crate::io::Io;
use crate::masp::utils::{
    IterProgress, MaspClient, PeekableIter, ProgressTracker,
};
use crate::masp::IndexedNoteEntry;
use crate::queries::testing::TestClient;
use crate::queries::{Client, EncodedResponseQuery, Rpc, RPC};

/// A viewing key derived from A_SPENDING_KEY
pub const AA_VIEWING_KEY: &str = "zvknam1qqqqqqqqqqqqqq9v0sls5r5de7njx8ehu49pqgmqr9ygelg87l5x8y4s9r0pjlvu6x74w9gjpw856zcu826qesdre628y6tjc26uhgj6d9zqur9l5u3p99d9ggc74ald6s8y3sdtka74qmheyqvdrasqpwyv2fsmxlz57lj4grm2pthzj3sflxc0jx0edrakx3vdcngrfjmru8ywkguru8mxss2uuqxdlglaz6undx5h8w7g70t2es850g48xzdkqay5qs0yw06rtxcpjdve6";

/// A serialized transaction that will work for testing.
/// Would love to do this in a less opaque fashion, but
/// making these things is a misery not worth my time.
///
/// This a tx sending 1 BTC from Albert to Albert's PA
pub(super) fn arbitrary_masp_tx() -> Transaction {
    Transaction::try_from_slice(&[
        2, 0, 0, 0, 10, 39, 167, 38, 166, 117, 255, 233, 0, 0, 0, 0, 255, 255,
        255, 255, 1, 162, 120, 217, 193, 173, 117, 92, 126, 107, 199, 182, 72,
        95, 60, 122, 52, 9, 134, 72, 4, 167, 41, 187, 171, 17, 124, 114, 84,
        191, 75, 37, 2, 0, 225, 245, 5, 0, 0, 0, 0, 93, 213, 181, 21, 38, 32,
        230, 52, 155, 4, 203, 26, 70, 63, 59, 179, 142, 7, 72, 76, 0, 0, 0, 1,
        132, 100, 41, 23, 128, 97, 116, 40, 195, 40, 46, 55, 79, 106, 234, 32,
        4, 216, 106, 88, 173, 65, 140, 99, 239, 71, 103, 201, 111, 149, 166,
        13, 73, 224, 253, 98, 27, 199, 11, 142, 56, 214, 4, 96, 35, 72, 83, 86,
        194, 107, 163, 194, 238, 37, 19, 171, 8, 129, 53, 246, 64, 220, 155,
        47, 177, 165, 109, 232, 84, 247, 128, 184, 40, 26, 113, 196, 190, 181,
        57, 213, 45, 144, 46, 12, 145, 128, 169, 116, 65, 51, 208, 239, 50,
        217, 224, 98, 179, 53, 18, 130, 183, 114, 225, 21, 34, 175, 144, 125,
        239, 240, 82, 100, 174, 1, 192, 32, 187, 208, 205, 31, 108, 59, 87,
        201, 148, 214, 244, 255, 8, 150, 100, 225, 11, 245, 221, 170, 85, 241,
        110, 50, 90, 151, 210, 169, 41, 3, 23, 160, 196, 117, 211, 217, 121, 9,
        42, 236, 19, 149, 94, 62, 163, 222, 172, 128, 197, 56, 100, 233, 227,
        239, 60, 182, 191, 55, 148, 17, 0, 168, 198, 84, 87, 191, 89, 229, 9,
        129, 165, 98, 200, 127, 225, 192, 58, 0, 92, 104, 97, 26, 125, 169,
        209, 40, 170, 29, 93, 16, 114, 174, 23, 233, 218, 112, 26, 175, 196,
        198, 197, 159, 167, 157, 16, 232, 247, 193, 44, 82, 143, 238, 179, 77,
        87, 153, 3, 33, 207, 215, 142, 104, 179, 17, 252, 148, 215, 150, 76,
        56, 169, 13, 240, 4, 195, 221, 45, 250, 24, 51, 243, 174, 176, 47, 117,
        38, 1, 124, 193, 191, 55, 11, 164, 97, 83, 188, 92, 202, 229, 106, 236,
        165, 85, 236, 95, 255, 28, 71, 18, 173, 202, 47, 63, 226, 129, 203,
        154, 54, 155, 177, 161, 106, 210, 220, 193, 142, 44, 105, 46, 164, 83,
        136, 63, 24, 172, 157, 117, 9, 202, 99, 223, 144, 36, 26, 154, 84, 175,
        119, 12, 102, 71, 33, 14, 131, 250, 86, 215, 153, 18, 94, 213, 61, 196,
        67, 132, 204, 89, 235, 241, 188, 147, 236, 92, 46, 83, 169, 236, 12,
        34, 33, 65, 243, 18, 23, 29, 41, 252, 207, 17, 196, 55, 56, 141, 158,
        116, 227, 195, 159, 233, 72, 26, 69, 72, 213, 50, 101, 161, 127, 213,
        35, 210, 223, 201, 219, 198, 192, 125, 129, 222, 178, 241, 116, 59,
        255, 72, 163, 46, 21, 222, 74, 202, 117, 217, 22, 188, 203, 2, 150, 38,
        78, 78, 250, 45, 36, 225, 240, 227, 115, 33, 114, 189, 25, 9, 219, 239,
        57, 103, 19, 109, 11, 5, 156, 43, 35, 53, 219, 250, 215, 185, 173, 11,
        101, 221, 29, 130, 74, 110, 225, 183, 77, 13, 52, 90, 183, 93, 212,
        175, 132, 21, 229, 109, 188, 124, 103, 3, 39, 174, 140, 115, 67, 49,
        100, 231, 129, 32, 24, 201, 196, 247, 33, 155, 20, 139, 34, 3, 183, 12,
        164, 6, 10, 219, 207, 151, 160, 4, 201, 160, 12, 156, 82, 142, 226, 19,
        134, 144, 53, 220, 140, 61, 74, 151, 129, 102, 214, 73, 107, 147, 4,
        98, 68, 79, 225, 103, 242, 187, 170, 102, 225, 114, 4, 87, 96, 7, 212,
        150, 127, 211, 158, 54, 86, 15, 191, 21, 116, 202, 195, 60, 65, 134,
        22, 2, 44, 133, 64, 181, 121, 66, 218, 227, 72, 148, 63, 108, 227, 33,
        66, 239, 77, 127, 139, 31, 16, 150, 119, 198, 119, 229, 88, 188, 113,
        80, 222, 86, 122, 181, 142, 186, 130, 125, 236, 166, 95, 134, 243, 128,
        65, 169, 33, 65, 73, 182, 183, 156, 248, 39, 46, 199, 181, 85, 96, 126,
        155, 189, 10, 211, 145, 230, 94, 69, 232, 74, 87, 211, 46, 216, 30, 24,
        38, 104, 192, 165, 28, 73, 36, 227, 194, 41, 168, 5, 181, 176, 112, 67,
        92, 158, 212, 129, 207, 182, 223, 59, 185, 84, 210, 147, 32, 29, 61,
        56, 185, 21, 156, 114, 34, 115, 29, 25, 89, 152, 56, 55, 238, 43, 0,
        114, 89, 79, 95, 104, 143, 180, 51, 53, 108, 223, 236, 59, 47, 188,
        174, 196, 101, 180, 207, 162, 198, 104, 52, 67, 132, 178, 9, 40, 10,
        88, 206, 25, 132, 60, 136, 13, 213, 223, 81, 196, 131, 118, 15, 53,
        125, 165, 177, 170, 170, 17, 94, 53, 151, 51, 16, 170, 23, 118, 255,
        26, 46, 47, 37, 73, 165, 26, 43, 10, 221, 4, 132, 15, 78, 214, 161, 3,
        220, 10, 87, 139, 85, 61, 39, 131, 242, 216, 235, 52, 93, 46, 180, 196,
        151, 54, 207, 80, 223, 90, 252, 77, 10, 122, 175, 229, 7, 144, 41, 1,
        162, 120, 217, 193, 173, 117, 92, 126, 107, 199, 182, 72, 95, 60, 122,
        52, 9, 134, 72, 4, 167, 41, 187, 171, 17, 124, 114, 84, 191, 75, 37, 2,
        0, 31, 10, 250, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169,
        172, 15, 195, 104, 140, 79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27,
        172, 88, 108, 85, 232, 63, 249, 122, 26, 239, 251, 58, 240, 10, 219,
        34, 198, 187, 147, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160,
        136, 39, 79, 101, 89, 107, 208, 208, 153, 32, 182, 26, 181, 218, 97,
        187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148, 93, 87, 229, 172, 125,
        5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5, 39,
        45, 197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100,
        122, 227, 209, 119, 11, 172, 3, 38, 168, 5, 187, 239, 212, 128, 86,
        200, 193, 33, 189, 184, 151, 241, 211, 167, 49, 151, 215, 148, 38, 149,
        99, 140, 79, 169, 172, 15, 195, 104, 140, 79, 151, 116, 185, 5, 161,
        78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26, 239, 251,
        58, 240, 10, 219, 34, 198, 187, 37, 197, 248, 90, 113, 62, 149, 117,
        145, 118, 42, 241, 60, 208, 83, 57, 96, 143, 17, 128, 92, 118, 158,
        188, 77, 37, 184, 164, 135, 246, 196, 57, 198, 106, 139, 33, 15, 207,
        0, 101, 143, 92, 178, 132, 19, 106, 221, 246, 176, 100, 20, 114, 26,
        55, 163, 14, 173, 255, 121, 181, 58, 121, 140, 3,
    ])
    .expect("Test failed")
}

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
