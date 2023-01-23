use tendermint::block::Height;
use tendermint_rpc::endpoint::{block, block_results, abci_info, blockchain, commit, consensus_params, consensus_state, health, net_info, status};
use tendermint_rpc::query::Query;
use tendermint_rpc::Order;
use thiserror::Error;

use crate::ledger::events::log::EventLog;
use crate::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use crate::ledger::storage_api;
use crate::tendermint::merkle::proof::Proof;
use crate::types::storage::BlockHeight;
#[cfg(feature = "wasm-runtime")]
use crate::vm::wasm::{TxCache, VpCache};
#[cfg(feature = "wasm-runtime")]
use crate::vm::WasmCacheRoAccess;

use crate::tendermint_rpc::error::Error as RpcError;
/// A request context provides read-only access to storage and WASM compilation
/// caches to request handlers.
#[derive(Debug, Clone)]
pub struct RequestCtx<'shell, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    /// Reference to the ledger's [`Storage`].
    pub storage: &'shell Storage<D, H>,
    /// Log of events emitted by `FinalizeBlock` ABCI calls.
    pub event_log: &'shell EventLog,
    /// Cache of VP wasm compiled artifacts.
    #[cfg(feature = "wasm-runtime")]
    pub vp_wasm_cache: VpCache<WasmCacheRoAccess>,
    /// Cache of transaction wasm compiled artifacts.
    #[cfg(feature = "wasm-runtime")]
    pub tx_wasm_cache: TxCache<WasmCacheRoAccess>,
    /// Taken from config `storage_read_past_height_limit`. When set, will
    /// limit the how many block heights in the past can the storage be
    /// queried for reading values.
    pub storage_read_past_height_limit: Option<u64>,
}

/// A `Router` handles parsing read-only query requests and dispatching them to
/// their handler functions. A valid query returns a borsh-encoded result.
pub trait Router {
    /// Handle a given request using the provided context. This must be invoked
    /// on the root `Router` to be able to match the `request.path` fully.
    fn handle<D, H>(
        &self,
        ctx: RequestCtx<'_, D, H>,
        request: &RequestQuery,
    ) -> storage_api::Result<EncodedResponseQuery>
    where
        D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync,
    {
        self.internal_handle(ctx, request, 0)
    }

    /// Internal method which shouldn't be invoked directly. Instead, you may
    /// want to call `self.handle()`.
    ///
    /// Handle a given request using the provided context, starting to
    /// try to match `request.path` against the `Router`'s patterns at the
    /// given `start` offset.
    fn internal_handle<D, H>(
        &self,
        ctx: RequestCtx<'_, D, H>,
        request: &RequestQuery,
        start: usize,
    ) -> storage_api::Result<EncodedResponseQuery>
    where
        D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync;
}

/// A client with async request dispatcher method, which can be used to invoke
/// type-safe methods from a root [`Router`], generated via `router!` macro.
#[cfg(any(test, feature = "async-client"))]
#[async_trait::async_trait(?Send)]
pub trait Client {
    /// `std::io::Error` can happen in decoding with
    /// `BorshDeserialize::try_from_slice`
    type Error: From<std::io::Error>;

    /// Send a simple query request at the given path. For more options, use the
    /// `request` method.
    async fn simple_request(
        &self,
        path: String,
    ) -> Result<Vec<u8>, Self::Error> {
        self.request(path, None, None, false)
            .await
            .map(|response| response.data)
    }

    /// Send a query request at the given path.
    async fn request(
        &self,
        path: String,
        data: Option<Vec<u8>>,
        height: Option<BlockHeight>,
        prove: bool,
    ) -> Result<EncodedResponseQuery, Self::Error>;

    /// `/abci_info`: get information about the ABCI application.
    async fn abci_info(&self) -> Result<abci_info::AbciInfo, Error> {
        Ok(self.perform(abci_info::Request).await?.response)
    }

    /// `/broadcast_tx_sync`: broadcast a transaction, returning the response
    /// from `CheckTx`.
    async fn broadcast_tx_sync(
        &self,
        tx: tendermint::abci::Transaction,
    ) -> Result<tendermint_rpc::endpoint::broadcast::tx_sync::Response, RpcError>
    {
        self.perform(
            tendermint_rpc::endpoint::broadcast::tx_sync::Request::new(tx),
        )
        .await
    }

    /// `/block`: get the latest block.
    async fn latest_block(&self) -> Result<block::Response, RpcError> {
        self.perform(block::Request::default()).await
    }

    /// `/block`: get block at a given height.
    async fn block<H>(&self, height: H) -> Result<block::Response, RpcError>
    where
        H: Into<Height> + Send,
    {
        self.perform(block::Request::new(height.into())).await
    }

    /// `/block_search`: search for blocks by BeginBlock and EndBlock events.
    async fn block_search(
        &self,
        query: Query,
        page: u32,
        per_page: u8,
        order: Order,
    ) -> Result<tendermint_rpc::endpoint::block_search::Response, RpcError>
    {
        self.perform(tendermint_rpc::endpoint::block_search::Request::new(
            query, page, per_page, order,
        ))
        .await
    }

    /// `/block_results`: get ABCI results for a block at a particular height.
    async fn block_results<H>(
        &self,
        height: H,
    ) -> Result<tendermint_rpc::endpoint::block_results::Response, RpcError>
    where
        H: Into<Height> + Send,
    {
        self.perform(tendermint_rpc::endpoint::block_results::Request::new(
            height.into(),
        ))
        .await
    }

    /// `/tx_search`: search for transactions with their results.
    async fn tx_search(
        &self,
        query: Query,
        prove: bool,
        page: u32,
        per_page: u8,
        order: Order,
    ) -> Result<tendermint_rpc::endpoint::tx_search::Response, RpcError> {
        self.perform(tendermint_rpc::endpoint::tx_search::Request::new(
            query, prove, page, per_page, order,
        ))
        .await
    }

    /// `/abci_query`: query the ABCI application
    async fn abci_query<V>(
        &self,
        path: Option<tendermint::abci::Path>,
        data: V,
        height: Option<Height>,
        prove: bool,
    ) -> Result<tendermint_rpc::endpoint::abci_query::AbciQuery, RpcError>
    where
        V: Into<Vec<u8>> + Send,
    {
        Ok(self
            .perform(tendermint_rpc::endpoint::abci_query::Request::new(
                path, data, height, prove,
            ))
            .await?
            .response)
    }

    /// `/block_results`: get ABCI results for the latest block.
    async fn latest_block_results(&self) -> Result<block_results::Response, RpcError> {
        self.perform(block_results::Request::default()).await
    }

    /// `/blockchain`: get block headers for `min` <= `height` <= `max`.
    ///
    /// Block headers are returned in descending order (highest first).
    ///
    /// Returns at most 20 items.
    async fn blockchain<H>(&self, min: H, max: H) -> Result<blockchain::Response, RpcError>
    where
        H: Into<Height> + Send,
    {
        // TODO(tarcieri): return errors for invalid params before making request?
        self.perform(blockchain::Request::new(min.into(), max.into()))
            .await
    }

    /// `/commit`: get block commit at a given height.
    async fn commit<H>(&self, height: H) -> Result<commit::Response, RpcError>
    where
        H: Into<Height> + Send,
    {
        self.perform(commit::Request::new(height.into())).await
    }

    /// `/consensus_params`: get current consensus parameters at the specified
    /// height.
    async fn consensus_params<H>(&self, height: H) -> Result<consensus_params::Response, RpcError>
    where
        H: Into<Height> + Send,
    {
        self.perform(consensus_params::Request::new(Some(height.into())))
            .await
    }

    /// `/consensus_state`: get current consensus state
    async fn consensus_state(&self) -> Result<consensus_state::Response, RpcError> {
        self.perform(consensus_state::Request::new()).await
    }

    /// `/consensus_params`: get the latest consensus parameters.
    async fn latest_consensus_params(&self) -> Result<consensus_params::Response, RpcError> {
        self.perform(consensus_params::Request::new(None)).await
    }

    /// `/commit`: get the latest block commit
    async fn latest_commit(&self) -> Result<commit::Response, RpcError> {
        self.perform(commit::Request::default()).await
    }

    /// `/health`: get node health.
    ///
    /// Returns empty result (200 OK) on success, no response in case of an error.
    async fn health(&self) -> Result<(), Error> {
        self.perform(health::Request).await?;
        Ok(())
    }

    /// `/net_info`: obtain information about P2P and other network connections.
    async fn net_info(&self) -> Result<net_info::Response, RpcError> {
        self.perform(net_info::Request).await
    }

    /// `/status`: get Tendermint status including node info, pubkey, latest
    /// block hash, app hash, block height and time.
    async fn status(&self) -> Result<status::Response, RpcError> {
        self.perform(status::Request).await
    }

    /// Perform a request against the RPC endpoint
    async fn perform<R>(&self, request: R) -> Result<R::Response, RpcError>
    where
        R: tendermint_rpc::SimpleRequest;
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Tendermint(#[from] tendermint_rpc::Error),
    #[error("Decoding error: {0}")]
    Decoding(#[from] std::io::Error),
    #[error("Info log: {0}, error code: {1}")]
    Query(String, u32),
    #[error("Invalid block height: {0} (overflown i64)")]
    InvalidHeight(BlockHeight),
}

#[async_trait::async_trait(?Send)]
impl<C: tendermint_rpc::Client + std::marker::Sync> Client for C {
    type Error = Error;

    async fn request(
        &self,
        path: String,
        data: Option<Vec<u8>>,
        height: Option<BlockHeight>,
        prove: bool,
    ) -> Result<EncodedResponseQuery, Self::Error> {
        let data = data.unwrap_or_default();
        let height = height
            .map(|height| {
                tendermint::block::Height::try_from(height.0)
                    .map_err(|_err| Error::InvalidHeight(height))
            })
            .transpose()?;
        let response = self
            .abci_query(
                // TODO open the private Path constructor in tendermint-rpc
                Some(std::str::FromStr::from_str(&path).unwrap()),
                data,
                height,
                prove,
            )
            .await?;
        use tendermint::abci::Code;
        match response.code {
            Code::Ok => Ok(EncodedResponseQuery {
                data: response.value,
                info: response.info,
                proof: response.proof,
            }),
            Code::Err(code) => Err(Error::Query(response.info, code)),
        }
    }

    async fn perform<R>(&self, request: R) -> Result<R::Response, RpcError>
    where
        R: tendermint_rpc::SimpleRequest,
    {
        tendermint_rpc::Client::perform(self, request).await
    }
}

/// Temporary domain-type for `tendermint_proto::abci::RequestQuery`, copied
/// from <https://github.com/informalsystems/tendermint-rs/pull/862>
/// until we are on a branch that has it included.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RequestQuery {
    /// Raw query bytes.
    ///
    /// Can be used with or in lieu of `path`.
    pub data: Vec<u8>,
    /// Path of the request, like an HTTP `GET` path.
    ///
    /// Can be used with or in lieu of `data`.
    ///
    /// Applications MUST interpret `/store` as a query by key on the
    /// underlying store. The key SHOULD be specified in the Data field.
    /// Applications SHOULD allow queries over specific types like
    /// `/accounts/...` or `/votes/...`.
    pub path: String,
    /// The block height for which the query should be executed.
    ///
    /// The default `0` returns data for the latest committed block. Note that
    /// this is the height of the block containing the application's Merkle
    /// root hash, which represents the state as it was after committing
    /// the block at `height - 1`.
    pub height: BlockHeight,
    /// Whether to return a Merkle proof with the response, if possible.
    pub prove: bool,
}

/// Generic response from a query
#[derive(Clone, Debug, Default)]
pub struct ResponseQuery<T> {
    /// Response data to be borsh encoded
    pub data: T,
    /// Non-deterministic log of the request execution
    pub info: String,
    /// Optional proof - used for storage value reads which request `prove`
    pub proof: Option<Proof>,
}

/// [`ResponseQuery`] with borsh-encoded `data` field
pub type EncodedResponseQuery = ResponseQuery<Vec<u8>>;

impl RequestQuery {
    /// Try to convert tendermint RequestQuery into our [`RequestQuery`]
    /// domain type. This tries to convert the block height into our
    /// [`BlockHeight`] type, where `0` is treated as a special value to signal
    /// to use the latest committed block height as per tendermint ABCI Query
    /// spec. A negative block height will cause an error.
    pub fn try_from_tm<D, H>(
        storage: &Storage<D, H>,
        crate::tendermint_proto::abci::RequestQuery {
            data,
            path,
            height,
            prove,
        }: crate::tendermint_proto::abci::RequestQuery,
    ) -> Result<Self, String>
    where
        D: DB + for<'iter> DBIter<'iter>,
        H: StorageHasher,
    {
        let height = match height {
            0 => {
                // `0` means last committed height
                storage.last_height
            }
            _ => BlockHeight(height.try_into().map_err(|_| {
                format!("Query height cannot be negative, got: {}", height)
            })?),
        };
        Ok(Self {
            data,
            path,
            height,
            prove,
        })
    }
}
