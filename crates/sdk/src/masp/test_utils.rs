use std::ops::{Deref, DerefMut};

use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use namada_core::storage::{BlockHeight, IndexedTx};
use namada_state::LastBlock;
use tendermint_rpc::SimpleRequest;

use crate::error::Error;
use crate::io::Io;
use crate::masp::types::IndexedNoteEntry;
use crate::masp::utils::{
    CommitmentTreeUpdates, FetchQueueSender, MaspClient, ProgressLogger,
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
        },
        sender,
    )
}

#[derive(Debug, Clone)]
pub struct TestingMaspClient {
    next_masp_txs: flume::Receiver<Option<IndexedNoteEntry>>,
}

impl<'a> MaspClient<'a, TestingClient> for TestingMaspClient {
    fn new(client: &'a TestingClient) -> Self
    where
        Self: 'a,
    {
        Self {
            next_masp_txs: client.next_masp_txs.clone(),
        }
    }

    async fn witness_map_updates<U: ShieldedUtils, IO: Io>(
        &self,
        _: &ShieldedContext<U>,
        _: &IO,
        _: IndexedTx,
        _: BlockHeight,
    ) -> Result<CommitmentTreeUpdates, Error> {
        Ok(CommitmentTreeUpdates {
            commitment_tree: CommitmentTree::<Node>::empty(),
            witness_map: Default::default(),
            note_map_delta: Default::default(),
        })
    }

    async fn fetch_shielded_transfer<IO: Io>(
        &self,
        logger: &impl ProgressLogger<IO>,
        mut tx_sender: FetchQueueSender,
        from: u64,
        to: u64,
    ) -> Result<(), Error> {
        // N.B. this assumes one masp tx per block
        for _ in logger.fetch(from..=to) {
            let next_tx =
                self.next_masp_txs.recv().expect("Test failed").ok_or_else(
                    || {
                        Error::Other(
                            "Connection to fetch MASP txs failed".to_string(),
                        )
                    },
                )?;
            tx_sender.send(next_tx);
        }
        Ok(())
    }
}
