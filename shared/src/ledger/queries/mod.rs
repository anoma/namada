//! Ledger read-only queries can be handled and dispatched via the [`RPC`]
//! defined via `router!` macro.

use shell::{Shell, SHELL};
#[cfg(any(test, feature = "async-client"))]
pub use types::Client;
pub use types::{
    EncodedResponseQuery, RequestCtx, RequestQuery, ResponseQuery, Router,
};

use super::storage::{DBIter, StorageHasher, DB};
use super::storage_api;

#[macro_use]
mod router;
mod shell;
mod types;

// Most commonly expected patterns should be declared first
router! {RPC,
    // Shell provides storage read access, block metadata and can dry-run a tx
    ( "shell" ) = (sub SHELL),
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
    if request.height != ctx.storage.last_height {
        return Err(storage_api::Error::new_const(
            "This query doesn't support arbitrary block heights, only the \
             latest committed block height ('0' can be used as a special \
             value that means the latest block height)",
        ));
    }
    Ok(())
}

/// For queries that only support latest height, check that the given height is
/// not different from latest height, otherwise return an error.
pub fn require_no_proof(request: &RequestQuery) -> storage_api::Result<()> {
    if request.prove {
        return Err(storage_api::Error::new_const(
            "This query doesn't support proofs",
        ));
    }
    Ok(())
}

#[cfg(any(test, feature = "tendermint-rpc"))]
/// Provides [`Client`] implementation for Tendermint RPC client
pub mod tm {
    use thiserror::Error;

    use super::*;
    use crate::types::storage::BlockHeight;

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

    #[async_trait::async_trait]
    impl Client for tendermint_rpc::HttpClient {
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
            let response = tendermint_rpc::Client::abci_query(
                self,
                // TODO open the private Path constructor in tendermint-rpc
                Some(std::str::FromStr::from_str(&path).unwrap()),
                data,
                height,
                prove,
            )
            .await?;
            match response.code {
                tendermint::abci::Code::Ok => Ok(EncodedResponseQuery {
                    data: response.value,
                    info: response.info,
                    proof_ops: response.proof.map(Into::into),
                }),
                tendermint::abci::Code::Err(code) => {
                    Err(Error::Query(response.info, code))
                }
            }
        }
    }
}

/// Queries testing helpers
#[cfg(any(test, feature = "testing"))]
mod testing {
    use tempfile::TempDir;

    use super::*;
    use crate::ledger::storage::testing::TestStorage;
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
        pub storage: TestStorage,
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
            let storage = TestStorage::default();
            let (vp_wasm_cache, vp_cache_dir) =
                wasm::compilation_cache::common::testing::cache();
            let (tx_wasm_cache, tx_cache_dir) =
                wasm::compilation_cache::common::testing::cache();
            Self {
                rpc,
                storage,
                vp_wasm_cache: vp_wasm_cache.read_only(),
                tx_wasm_cache: tx_wasm_cache.read_only(),
                vp_cache_dir,
                tx_cache_dir,
            }
        }
    }

    #[async_trait::async_trait]
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
                storage: &self.storage,
                vp_wasm_cache: self.vp_wasm_cache.clone(),
                tx_wasm_cache: self.tx_wasm_cache.clone(),
            };
            let response = self.rpc.handle(ctx, &request).unwrap();
            Ok(response)
        }
    }
}
