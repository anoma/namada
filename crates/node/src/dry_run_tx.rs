//! The ledger modules

use std::cell::RefCell;

use namada_gas::Gas;
use namada_sdk::queries::{EncodedResponseQuery, RequestCtx, RequestQuery};
use namada_state::{DBIter, ResultExt, StorageHasher, DB};
use namada_tx::data::{DryRunResult, ExtendedTxResult, GasLimit, TxResult};

use super::protocol;
use crate::vm::wasm::{TxCache, VpCache};
use crate::vm::WasmCacheAccess;

/// Dry run a transaction
pub fn dry_run_tx<'a, D, H, CA>(
    mut ctx: RequestCtx<'a, D, H, VpCache<CA>, TxCache<CA>>,
    request: &RequestQuery,
) -> namada_state::StorageResult<EncodedResponseQuery>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    use borsh_ext::BorshSerializeExt;
    use namada_gas::{GasMetering, TxGasMeter};
    use namada_tx::data::TxType;
    use namada_tx::Tx;

    use crate::ledger::protocol::ShellParams;
    use crate::storage::TxIndex;

    let mut temp_state = ctx.state.with_temp_write_log();
    let tx = Tx::try_from(&request.data[..]).into_storage_result()?;
    tx.validate_tx().into_storage_result()?;

    let gas_scale = namada_parameters::get_gas_scale(ctx.state)?;

    // Wrapper dry run to allow estimating the gas cost of a transaction
    let (wrapper_hash, extended_tx_result, tx_gas_meter) =
        match tx.header().tx_type {
            TxType::Wrapper(wrapper) => {
                let gas_limit = wrapper
                    .gas_limit
                    .as_scaled_gas(gas_scale)
                    .into_storage_result()?;
                let tx_gas_meter = RefCell::new(TxGasMeter::new(gas_limit));
                let tx_result = protocol::apply_wrapper_tx(
                    &tx,
                    &wrapper,
                    &request.data,
                    &tx_gas_meter,
                    &mut temp_state,
                    None,
                )
                .into_storage_result()?;

                temp_state.write_log_mut().commit_tx_to_batch();
                let available_gas = tx_gas_meter.borrow().get_available_gas();
                (
                    Some(tx.header_hash()),
                    tx_result,
                    TxGasMeter::new(available_gas),
                )
            }
            _ => {
                // If dry run only the inner tx, use the max block gas as
                // the gas limit
                let max_block_gas =
                    namada_parameters::get_max_block_gas(ctx.state)?;
                let gas_limit = GasLimit::from(max_block_gas)
                    .as_scaled_gas(gas_scale)
                    .into_storage_result()?;
                (
                    None,
                    TxResult::default().to_extended_result(None),
                    TxGasMeter::new(gas_limit),
                )
            }
        };

    let ExtendedTxResult {
        mut tx_result,
        ref masp_tx_refs,
        ref ibc_tx_data_refs,
    } = extended_tx_result;
    let tx_gas_meter = RefCell::new(tx_gas_meter);
    for cmt in tx.commitments() {
        let batched_tx = tx.batch_ref_tx(cmt);
        let batched_tx_result = protocol::apply_wasm_tx(
            batched_tx,
            &TxIndex(0),
            ShellParams::new(
                &tx_gas_meter,
                &mut temp_state,
                &mut ctx.vp_wasm_cache,
                &mut ctx.tx_wasm_cache,
            ),
        );
        let is_accepted =
            matches!(&batched_tx_result, Ok(result) if result.is_accepted());
        if is_accepted {
            temp_state.write_log_mut().commit_tx_to_batch();
        } else {
            temp_state.write_log_mut().drop_tx();
        }
        tx_result.insert_inner_tx_result(
            wrapper_hash.as_ref(),
            either::Right(cmt),
            batched_tx_result,
        );
    }
    // Account gas for both batch and wrapper
    tx_result.gas_used = tx_gas_meter
        .borrow()
        .get_tx_consumed_gas()
        .get_whole_gas_units(gas_scale);
    let tx_result_string = tx_result.to_result_string();
    let dry_run_result = DryRunResult(tx_result_string, gas_used);

    Ok(EncodedResponseQuery {
        data: dry_run_result.serialize_to_vec(),
        proof: None,
        info: Default::default(),
        height: ctx.state.in_mem().get_last_block_height(),
    })
}

#[cfg(test)]
mod test {
    use borsh::BorshDeserialize;
    use borsh_ext::BorshSerializeExt;
    use namada_core::address;
    use namada_core::hash::Hash;
    use namada_core::storage::{BlockHeight, Key};
    use namada_sdk::queries::{
        EncodedResponseQuery, RequestCtx, RequestQuery, Router, RPC,
    };
    use namada_sdk::tendermint_rpc::{Error as RpcError, Response};
    use namada_state::testing::TestState;
    use namada_state::StorageWrite;
    use namada_test_utils::TestWasms;
    use namada_tx::data::TxType;
    use namada_tx::{Code, Data, Tx};
    use tempfile::TempDir;

    use crate::ledger::events::log::EventLog;
    use crate::ledger::queries::Client;
    use crate::token;
    use crate::vm::wasm::{TxCache, VpCache};
    use crate::vm::{wasm, WasmCacheRoAccess};

    /// A test client that has direct access to the storage
    pub struct TestClient<RPC>
    where
        RPC: Router,
    {
        /// RPC router
        pub rpc: RPC,
        /// state
        pub state: TestState,
        /// event log
        pub event_log: EventLog,
        /// VP wasm compilation cache
        pub vp_wasm_cache: VpCache<WasmCacheRoAccess>,
        /// tx wasm compilation cache
        pub tx_wasm_cache: TxCache<WasmCacheRoAccess>,
        /// VP wasm compilation cache directory
        #[allow(dead_code)] // never read
        pub vp_cache_dir: TempDir,
        /// tx wasm compilation cache directory
        #[allow(dead_code)] // never read
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
            let mut state = TestState::default();

            // Initialize mock gas limit
            let max_block_gas_key =
                namada_parameters::storage::get_max_block_gas_key();
            state
                .db_write(&max_block_gas_key, 20_000_000_u64.serialize_to_vec())
                .expect(
                    "Max block gas parameter must be initialized in storage",
                );
            // Initialize mock gas scale
            let gas_scale_key = namada_parameters::storage::get_gas_scale_key();
            state
                .db_write(&gas_scale_key, 100_000_000_u64.serialize_to_vec())
                .expect("Gas scale parameter must be initialized in storage");

            let event_log = EventLog::default();
            let (vp_wasm_cache, vp_cache_dir) =
                wasm::compilation_cache::common::testing::cache();
            let (tx_wasm_cache, tx_cache_dir) =
                wasm::compilation_cache::common::testing::cache();
            Self {
                rpc,
                state,
                event_log,
                vp_wasm_cache: vp_wasm_cache.read_only(),
                tx_wasm_cache: tx_wasm_cache.read_only(),
                vp_cache_dir,
                tx_cache_dir,
            }
        }
    }

    #[cfg_attr(feature = "async-send", async_trait::async_trait)]
    #[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
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
                data: data.into(),
                path,
                height: height.try_into().unwrap(),
                prove,
            };
            let ctx = RequestCtx {
                state: &self.state,
                event_log: &self.event_log,
                vp_wasm_cache: self.vp_wasm_cache.clone(),
                tx_wasm_cache: self.tx_wasm_cache.clone(),
                storage_read_past_height_limit: None,
            };
            // TODO(namada#3240): this is a hack to propagate errors to the
            // caller, we should really permit error types other
            // than [`std::io::Error`]
            if request.path == RPC.shell().dry_run_tx_path() {
                super::dry_run_tx(ctx, &request)
            } else {
                self.rpc.handle(ctx, &request)
            }
            .map_err(|err| {
                std::io::Error::new(std::io::ErrorKind::Other, err.to_string())
            })
        }

        async fn perform<R>(&self, _request: R) -> Result<R::Output, RpcError>
        where
            R: namada_sdk::tendermint_rpc::SimpleRequest,
        {
            Ok(R::Response::from_string("TODO").unwrap().into())
        }
    }

    #[tokio::test]
    async fn test_shell_queries_router_with_client()
    -> namada_state::StorageResult<()> {
        // Initialize the `TestClient`
        let mut client = TestClient::new(RPC);
        // store the wasm code
        let tx_no_op = TestWasms::TxNoOp.read_bytes();
        let tx_hash = Hash::sha256(&tx_no_op);
        let key = Key::wasm_code(&tx_hash);
        let len_key = Key::wasm_code_len(&tx_hash);
        client
            .state
            .db_write(&key, &tx_no_op.serialize_to_vec())
            .unwrap();
        client
            .state
            .db_write(&len_key, (tx_no_op.len() as u64).serialize_to_vec())
            .unwrap();

        // Request last committed epoch
        let read_epoch = RPC.shell().epoch(&client).await.unwrap();
        let current_epoch = client.state.in_mem().last_epoch;
        assert_eq!(current_epoch, read_epoch);

        // Request dry run tx
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = client.state.in_mem().chain_id.clone();
        outer_tx.set_code(Code::from_hash(tx_hash, None));
        outer_tx.set_data(Data::new(vec![]));
        let cmt = outer_tx.first_commitments().unwrap();
        let tx_bytes = outer_tx.to_bytes();
        let result = RPC
            .shell()
            .dry_run_tx(&client, Some(tx_bytes), None, false)
            .await
            .unwrap();
        assert!(
            result
                .data
                .0
                .get_inner_tx_result(None, either::Right(cmt))
                .unwrap()
                .as_ref()
                .unwrap()
                .is_accepted()
        );

        // Request storage value for a balance key ...
        let token_addr = address::testing::established_address_1();
        let owner = address::testing::established_address_2();
        let balance_key = token::storage_key::balance_key(&token_addr, &owner);
        // ... there should be no value yet.
        let read_balance = RPC
            .shell()
            .storage_value(&client, None, None, false, &balance_key)
            .await
            .unwrap();
        assert!(read_balance.data.is_empty());

        // Request storage prefix iterator
        let balance_prefix = token::storage_key::balance_prefix(&token_addr);
        let read_balances = RPC
            .shell()
            .storage_prefix(&client, None, None, false, &balance_prefix)
            .await
            .unwrap();
        assert!(read_balances.data.is_empty());

        // Request storage has key
        let has_balance_key = RPC
            .shell()
            .storage_has_key(&client, &balance_key)
            .await
            .unwrap();
        assert!(!has_balance_key);

        // Then write some balance ...
        let balance = token::Amount::native_whole(1000);
        StorageWrite::write(&mut client.state, &balance_key, balance)?;
        // It has to be committed to be visible in a query
        client.state.commit_tx_batch();
        client.state.commit_block().unwrap();
        // ... there should be the same value now
        let read_balance = RPC
            .shell()
            .storage_value(&client, None, None, false, &balance_key)
            .await
            .unwrap();
        assert_eq!(
            balance,
            token::Amount::try_from_slice(&read_balance.data).unwrap()
        );

        // Request storage prefix iterator
        let balance_prefix = token::storage_key::balance_prefix(&token_addr);
        let read_balances = RPC
            .shell()
            .storage_prefix(&client, None, None, false, &balance_prefix)
            .await
            .unwrap();
        assert_eq!(read_balances.data.len(), 1);

        // Request storage has key
        let has_balance_key = RPC
            .shell()
            .storage_has_key(&client, &balance_key)
            .await
            .unwrap();
        assert!(has_balance_key);

        Ok(())
    }
}
