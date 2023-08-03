//! Ledger read-only queries can be handled and dispatched via the [`RPC`]
//! defined via `router!` macro.

// Re-export to show in rustdoc!
pub use shell::Shell;
use shell::SHELL;
#[cfg(any(test, feature = "async-client"))]
pub use types::Client;
pub use types::{
    EncodedResponseQuery, Error, RequestCtx, RequestQuery, ResponseQuery,
    Router,
};
use vp::{Vp, VP};

pub use self::shell::eth_bridge::{
    Erc20FlowControl, GenBridgePoolProofReq, GenBridgePoolProofRsp,
};
use super::storage::traits::StorageHasher;
use super::storage::{DBIter, DB};
use super::storage_api;
use crate::types::storage::BlockHeight;

#[macro_use]
mod router;
mod shell;
mod types;
pub mod vp;

// Most commonly expected patterns should be declared first
router! {RPC,
    // Shell provides storage read access, block metadata and can dry-run a tx
    ( "shell" ) = (sub SHELL),

    // Validity-predicate's specific storage queries
    ( "vp" ) = (sub VP),
}

/// Handle RPC query request in the ledger. On success, returns response with
/// borsh-encoded data.
pub fn handle_path<D, H>(
    ctx: RequestCtx<'_, D, H>,
    request: &RequestQuery,
) -> storage_api::Result<EncodedResponseQuery>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    RPC.handle(ctx, request)
}

// Handler helpers:

/// For queries that only support latest height, check that the given height is
/// not different from latest height, otherwise return an error.
pub fn require_latest_height<D, H>(
    ctx: &RequestCtx<'_, D, H>,
    request: &RequestQuery,
) -> storage_api::Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if request.height != BlockHeight(0)
        && request.height != ctx.wl_storage.storage.get_last_block_height()
    {
        return Err(storage_api::Error::new_const(
            "This query doesn't support arbitrary block heights, only the \
             latest committed block height ('0' can be used as a special \
             value that means the latest block height)",
        ));
    }
    Ok(())
}

/// For queries that do not support proofs, check that proof is not requested,
/// otherwise return an error.
pub fn require_no_proof(request: &RequestQuery) -> storage_api::Result<()> {
    if request.prove {
        return Err(storage_api::Error::new_const(
            "This query doesn't support proofs",
        ));
    }
    Ok(())
}

/// For queries that don't use request data, require that there are no data
/// attached.
pub fn require_no_data(request: &RequestQuery) -> storage_api::Result<()> {
    if !request.data.is_empty() {
        return Err(storage_api::Error::new_const(
            "This query doesn't accept request data",
        ));
    }
    Ok(())
}

/// Queries testing helpers
#[cfg(any(test, feature = "testing"))]
mod testing {
    use tempfile::TempDir;
    use tendermint_rpc::Response;

    use super::*;
    use crate::ledger::events::log::EventLog;
    use crate::ledger::storage::testing::TestWlStorage;
    use crate::tendermint_rpc::error::Error as RpcError;
    use crate::types::storage::BlockHeight;
    use crate::vm::wasm::{self, TxCache, VpCache};
    use crate::vm::WasmCacheRoAccess;

    /// A test client that has direct access to the storage
    pub struct TestClient<RPC>
    where
        RPC: Router,
    {
        /// RPC router
        pub rpc: RPC,
        /// storage
        pub wl_storage: TestWlStorage,
        /// event log
        pub event_log: EventLog,
        /// VP wasm compilation cache
        pub vp_wasm_cache: VpCache<WasmCacheRoAccess>,
        /// tx wasm compilation cache
        pub tx_wasm_cache: TxCache<WasmCacheRoAccess>,
        /// VP wasm compilation cache directory
        pub vp_cache_dir: TempDir,
        /// tx wasm compilation cache directory
        pub tx_cache_dir: TempDir,
    }

    impl<RPC> TestClient<RPC>
    where
        RPC: Router,
    {
        #[allow(dead_code)]
        /// Initialize a test client for the given root RPC router
        pub fn new(rpc: RPC) -> Self {
            // Initialize the `TestClient`
            let wl_storage = TestWlStorage::default();
            let event_log = EventLog::default();
            let (vp_wasm_cache, vp_cache_dir) =
                wasm::compilation_cache::common::testing::cache();
            let (tx_wasm_cache, tx_cache_dir) =
                wasm::compilation_cache::common::testing::cache();
            Self {
                rpc,
                wl_storage,
                event_log,
                vp_wasm_cache: vp_wasm_cache.read_only(),
                tx_wasm_cache: tx_wasm_cache.read_only(),
                vp_cache_dir,
                tx_cache_dir,
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl<RPC> Client for TestClient<RPC>
    where
        RPC: Router + Sync,
    {
        type Error = std::io::Error;

        async fn request(
            &self,
            path: String,
            data: Option<Vec<u8>>,
            height: Option<BlockHeight>,
            prove: bool,
        ) -> Result<EncodedResponseQuery, Self::Error> {
            let data = data.unwrap_or_default();
            let height = height.unwrap_or_default();
            // Handle a path by invoking the `RPC.handle` directly with the
            // borrowed storage
            let request = RequestQuery {
                data,
                path,
                height,
                prove,
            };
            let ctx = RequestCtx {
                wl_storage: &self.wl_storage,
                event_log: &self.event_log,
                vp_wasm_cache: self.vp_wasm_cache.clone(),
                tx_wasm_cache: self.tx_wasm_cache.clone(),
                storage_read_past_height_limit: None,
            };
            // TODO: this is a hack to propagate errors to the caller, we should
            // really permit error types other than [`std::io::Error`]
            self.rpc.handle(ctx, &request).map_err(|err| {
                std::io::Error::new(std::io::ErrorKind::Other, err.to_string())
            })
        }

        async fn perform<R>(&self, _request: R) -> Result<R::Response, RpcError>
        where
            R: tendermint_rpc::SimpleRequest,
        {
            Response::from_string("TODO")
        }
    }
}
