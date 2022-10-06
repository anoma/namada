//! Ledger read-only queries can be handled and dispatched via the [`RPC`]
//! defined via `router!` macro.

use tendermint_proto::crypto::{ProofOp, ProofOps};
#[cfg(any(test, feature = "async-client"))]
pub use types::Client;
pub use types::{
    EncodedResponseQuery, RequestCtx, RequestQuery, ResponseQuery, Router,
};

use super::storage::{DBIter, StorageHasher, DB};
use super::storage_api::{self, ResultExt, StorageRead};
use crate::types::storage::{self, Epoch, PrefixValue};
use crate::types::transaction::TxResult;
#[cfg(all(feature = "wasm-runtime", feature = "ferveo-tpke"))]
use crate::types::transaction::{DecryptedTx, TxType};

#[macro_use]
mod router;
mod types;

// Most commonly expected patterns should be declared first
router! {RPC,
    // Epoch of the last committed block
    ( "epoch" ) -> Epoch = epoch,

    // Raw storage access - read value
    ( "value" / [storage_key: storage::Key] )
        -> Option<Vec<u8>> = storage_value,

    // Dry run a transaction
    ( "dry_run_tx" ) -> TxResult = dry_run_tx,

    // Raw storage access - prefix iterator
    ( "prefix" / [storage_key: storage::Key] )
        -> Vec<PrefixValue> = storage_prefix,

    // Raw storage access - is given storage key present?
    ( "has_key" / [storage_key: storage::Key] )
        -> bool = storage_has_key,
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

// Handlers:

#[cfg(all(feature = "wasm-runtime", feature = "ferveo-tpke"))]
fn dry_run_tx<D, H>(
    mut ctx: RequestCtx<'_, D, H>,
    request: &RequestQuery,
) -> storage_api::Result<ResponseQuery<TxResult>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    use super::gas::BlockGasMeter;
    use super::storage::write_log::WriteLog;
    use crate::proto::Tx;

    let mut gas_meter = BlockGasMeter::default();
    let mut write_log = WriteLog::default();
    let tx = Tx::try_from(&request.data[..]).into_storage_result()?;
    let tx = TxType::Decrypted(DecryptedTx::Decrypted(tx));
    let data = super::protocol::apply_tx(
        tx,
        request.data.len(),
        &mut gas_meter,
        &mut write_log,
        ctx.storage,
        &mut ctx.vp_wasm_cache,
        &mut ctx.tx_wasm_cache,
    )
    .into_storage_result()?;
    Ok(ResponseQuery {
        data,
        ..ResponseQuery::default()
    })
}

#[cfg(not(all(feature = "wasm-runtime", feature = "ferveo-tpke")))]
fn dry_run_tx<D, H>(
    _ctx: RequestCtx<'_, D, H>,
    _request: &RequestQuery,
) -> storage_api::Result<ResponseQuery<TxResult>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    unimplemented!(
        "dry_run_tx request handler requires \"wasm-runtime\" and \
         \"ferveo-tpke\" features enabled."
    )
}

fn epoch<D, H>(
    ctx: RequestCtx<'_, D, H>,
    request: &RequestQuery,
) -> storage_api::Result<ResponseQuery<Epoch>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    require_latest_height(&ctx, request)?;
    require_no_proof(request)?;

    let data = ctx.storage.last_epoch;
    Ok(ResponseQuery {
        data,
        ..Default::default()
    })
}

fn storage_value<D, H>(
    ctx: RequestCtx<'_, D, H>,
    request: &RequestQuery,
    storage_key: storage::Key,
) -> storage_api::Result<ResponseQuery<Option<Vec<u8>>>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    match ctx
        .storage
        .read_with_height(&storage_key, request.height)
        .into_storage_result()?
    {
        (Some(value), _gas) => {
            let proof = if request.prove {
                let proof = ctx
                    .storage
                    .get_existence_proof(
                        &storage_key,
                        value.clone().into(),
                        request.height,
                    )
                    .into_storage_result()?;
                Some(proof.into())
            } else {
                None
            };
            Ok(ResponseQuery {
                data: Some(value),
                proof_ops: proof,
                ..Default::default()
            })
        }
        (None, _gas) => {
            let proof = if request.prove {
                let proof = ctx
                    .storage
                    .get_non_existence_proof(&storage_key, request.height)
                    .into_storage_result()?;
                Some(proof.into())
            } else {
                None
            };
            Ok(ResponseQuery {
                data: None,
                proof_ops: proof,
                info: format!("No value found for key: {}", storage_key),
            })
        }
    }
}

fn storage_prefix<D, H>(
    ctx: RequestCtx<'_, D, H>,
    request: &RequestQuery,
    storage_key: storage::Key,
) -> storage_api::Result<ResponseQuery<Vec<storage::PrefixValue>>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    require_latest_height(&ctx, request)?;

    let (iter, _gas) = ctx.storage.iter_prefix(&storage_key);
    let data: storage_api::Result<Vec<PrefixValue>> = iter
        .map(|(key, value, _gas)| {
            let key = storage::Key::parse(key).into_storage_result()?;
            Ok(PrefixValue { key, value })
        })
        .collect();
    let data = data?;
    let proof_ops = if request.prove {
        let mut ops = vec![];
        for PrefixValue { key, value } in &data {
            let proof = ctx
                .storage
                .get_existence_proof(key, value.clone().into(), request.height)
                .into_storage_result()?;
            let mut cur_ops: Vec<ProofOp> =
                proof.ops.into_iter().map(|op| op.into()).collect();
            ops.append(&mut cur_ops);
        }
        // ops is not empty in this case
        Some(ProofOps { ops })
    } else {
        None
    };
    Ok(ResponseQuery {
        data,
        proof_ops,
        ..Default::default()
    })
}

fn storage_has_key<D, H>(
    ctx: RequestCtx<'_, D, H>,
    request: &RequestQuery,
    storage_key: storage::Key,
) -> storage_api::Result<ResponseQuery<bool>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    require_latest_height(&ctx, request)?;
    require_no_proof(request)?;

    let data = StorageRead::has_key(ctx.storage, &storage_key)?;
    Ok(ResponseQuery {
        data,
        ..Default::default()
    })
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

#[cfg(test)]
mod test {
    use borsh::BorshDeserialize;

    use super::testing::TestClient;
    use super::*;
    use crate::ledger::storage_api::StorageWrite;
    use crate::proto::Tx;
    use crate::types::{address, token};

    const TX_NO_OP_WASM: &str = "../wasm_for_tests/tx_no_op.wasm";

    #[test]
    fn test_queries_router_paths() {
        let path = RPC.epoch_path();
        assert_eq!("/epoch", path);

        let token_addr = address::testing::established_address_1();
        let owner = address::testing::established_address_2();
        let key = token::balance_key(&token_addr, &owner);
        let path = RPC.storage_value_path(&key);
        assert_eq!(format!("/value/{}", key), path);

        let path = RPC.dry_run_tx_path();
        assert_eq!("/dry_run_tx", path);

        let path = RPC.storage_prefix_path(&key);
        assert_eq!(format!("/prefix/{}", key), path);

        let path = RPC.storage_has_key_path(&key);
        assert_eq!(format!("/has_key/{}", key), path);
    }

    #[tokio::test]
    async fn test_queries_router_with_client() -> storage_api::Result<()> {
        // Initialize the `TestClient`
        let mut client = TestClient::new(RPC);

        // Request last committed epoch
        let read_epoch = RPC.epoch(&client).await.unwrap();
        let current_epoch = client.storage.last_epoch;
        assert_eq!(current_epoch, read_epoch);

        // Request dry run tx
        let tx_no_op = std::fs::read(TX_NO_OP_WASM).expect("cannot load wasm");
        let tx = Tx::new(tx_no_op, None);
        let tx_bytes = tx.to_bytes();
        let result = RPC
            .dry_run_tx_with_options(&client, Some(tx_bytes), None, false)
            .await
            .unwrap();
        assert!(result.data.is_accepted());

        // Request storage value for a balance key ...
        let token_addr = address::testing::established_address_1();
        let owner = address::testing::established_address_2();
        let balance_key = token::balance_key(&token_addr, &owner);
        // ... there should be no value yet.
        let read_balance =
            RPC.storage_value(&client, &balance_key).await.unwrap();
        assert!(read_balance.is_none());

        // Request storage prefix iterator
        let balance_prefix = token::balance_prefix(&token_addr);
        let read_balances =
            RPC.storage_prefix(&client, &balance_prefix).await.unwrap();
        assert!(read_balances.is_empty());

        // Request storage has key
        let has_balance_key =
            RPC.storage_has_key(&client, &balance_key).await.unwrap();
        assert!(!has_balance_key);

        // Then write some balance ...
        let balance = token::Amount::from(1000);
        StorageWrite::write(&mut client.storage, &balance_key, balance)?;
        // ... there should be the same value now
        let read_balance =
            RPC.storage_value(&client, &balance_key).await.unwrap();
        assert_eq!(
            balance,
            token::Amount::try_from_slice(&read_balance.unwrap()).unwrap()
        );

        // Request storage prefix iterator
        let balance_prefix = token::balance_prefix(&token_addr);
        let read_balances =
            RPC.storage_prefix(&client, &balance_prefix).await.unwrap();
        assert_eq!(read_balances.len(), 1);

        // Request storage has key
        let has_balance_key =
            RPC.storage_has_key(&client, &balance_key).await.unwrap();
        assert!(has_balance_key);

        Ok(())
    }
}
