use std::fmt::Debug;

use namada_core::storage::BlockHeight;
use namada_state::{DBIter, StorageHasher, WlState, DB};
use thiserror::Error;

use crate::events::log::EventLog;
use crate::tendermint::merkle::proof::ProofOps;
pub use crate::tendermint::v0_37::abci::request::Query as RequestQuery;
/// A request context provides read-only access to storage and WASM compilation
/// caches to request handlers.
#[derive(Debug, Clone)]
pub struct RequestCtx<'shell, D, H, VpCache, TxCache>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    /// Reference to the ledger's [`WlState`].
    pub state: &'shell WlState<D, H>,
    /// Log of events emitted by `FinalizeBlock` ABCI calls.
    pub event_log: &'shell EventLog,
    /// Cache of VP wasm compiled artifacts.
    pub vp_wasm_cache: VpCache,
    /// Cache of transaction wasm compiled artifacts.
    pub tx_wasm_cache: TxCache,
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
    fn handle<D, H, V, T>(
        &self,
        ctx: RequestCtx<'_, D, H, V, T>,
        request: &RequestQuery,
    ) -> namada_storage::Result<EncodedResponseQuery>
    where
        D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync,
    {
        if !request.path.is_ascii() {
            return Err(namada_storage::Error::SimpleMessage(
                "Non-ascii request paths are unsupported",
            ));
        }
        self.internal_handle(ctx, request, 0)
    }

    /// Internal method which shouldn't be invoked directly. Instead, you may
    /// want to call `self.handle()`.
    ///
    /// Handle a given request using the provided context, starting to
    /// try to match `request.path` against the `Router`'s patterns at the
    /// given `start` offset.
    fn internal_handle<D, H, V, T>(
        &self,
        ctx: RequestCtx<'_, D, H, V, T>,
        request: &RequestQuery,
        start: usize,
    ) -> namada_storage::Result<EncodedResponseQuery>
    where
        D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync;
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

/// Generic response from a query
#[derive(Clone, Debug, Default)]
pub struct ResponseQuery<T> {
    /// Response data to be borsh encoded
    pub data: T,
    /// Non-deterministic log of the request execution
    pub info: String,
    /// Optional proof - used for storage value reads which request `prove`
    pub proof: Option<ProofOps>,
}

/// [`ResponseQuery`] with borsh-encoded `data` field
pub type EncodedResponseQuery = ResponseQuery<Vec<u8>>;
