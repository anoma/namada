//! The ledger modules

pub use namada_sdk::{eth_bridge, events};
pub mod governance;
pub mod ibc;
pub mod native_vp;
pub mod pgf;
pub mod pos;
#[cfg(feature = "wasm-runtime")]
pub mod protocol;
pub use namada_sdk::queries;
pub mod storage;
pub mod vp_host_fns;

#[cfg(feature = "wasm-runtime")]
pub use dry_run_tx::dry_run_tx;
pub use namada_core::ledger::replay_protection;
pub use {
    namada_gas as gas, namada_parameters as parameters,
    namada_tx_env as tx_env, namada_vp_env as vp_env,
};

#[cfg(feature = "wasm-runtime")]
mod dry_run_tx {
    use namada_sdk::queries::{EncodedResponseQuery, RequestCtx, RequestQuery};
    use namada_state::{DBIter, ResultExt, StorageHasher, DB};
    use namada_tx::data::GasLimit;

    use super::protocol;
    use crate::vm::wasm::{TxCache, VpCache};
    use crate::vm::WasmCacheAccess;

    /// Dry run a transaction
    pub fn dry_run_tx<D, H, CA>(
        mut ctx: RequestCtx<'_, D, H, VpCache<CA>, TxCache<CA>>,
        request: &RequestQuery,
    ) -> namada_state::StorageResult<EncodedResponseQuery>
    where
        D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync,
        CA: 'static + WasmCacheAccess + Sync,
    {
        use borsh_ext::BorshSerializeExt;
        use namada_gas::{Gas, GasMetering, TxGasMeter};
        use namada_state::TempWlStorage;
        use namada_tx::data::{DecryptedTx, TxType};
        use namada_tx::Tx;

        use crate::ledger::protocol::ShellParams;
        use crate::types::storage::TxIndex;

        let mut tx = Tx::try_from(&request.data[..]).into_storage_result()?;
        tx.validate_tx().into_storage_result()?;

        let mut temp_wl_storage = TempWlStorage::new(&ctx.wl_storage.storage);
        let mut cumulated_gas = Gas::default();

        // Wrapper dry run to allow estimating the gas cost of a transaction
        let mut tx_gas_meter = match tx.header().tx_type {
            TxType::Wrapper(wrapper) => {
                let mut tx_gas_meter =
                    TxGasMeter::new(wrapper.gas_limit.to_owned());
                protocol::apply_wrapper_tx(
                    tx.clone(),
                    &wrapper,
                    None,
                    &request.data,
                    ShellParams::new(
                        &mut tx_gas_meter,
                        &mut temp_wl_storage,
                        &mut ctx.vp_wasm_cache,
                        &mut ctx.tx_wasm_cache,
                    ),
                    None,
                )
                .into_storage_result()?;

                temp_wl_storage.write_log.commit_tx();
                cumulated_gas = tx_gas_meter.get_tx_consumed_gas();

                tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
                TxGasMeter::new_from_sub_limit(tx_gas_meter.get_available_gas())
            }
            TxType::Protocol(_) | TxType::Decrypted(_) => {
                // If dry run only the inner tx, use the max block gas as the
                // gas limit
                TxGasMeter::new(GasLimit::from(
                    namada_parameters::get_max_block_gas(ctx.wl_storage)
                        .unwrap(),
                ))
            }
            TxType::Raw => {
                // Cast tx to a decrypted for execution
                tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted));

                // If dry run only the inner tx, use the max block gas as the
                // gas limit
                TxGasMeter::new(GasLimit::from(
                    namada_parameters::get_max_block_gas(ctx.wl_storage)
                        .unwrap(),
                ))
            }
        };

        let mut data = protocol::apply_wasm_tx(
            tx,
            &TxIndex(0),
            ShellParams::new(
                &mut tx_gas_meter,
                &mut temp_wl_storage,
                &mut ctx.vp_wasm_cache,
                &mut ctx.tx_wasm_cache,
            ),
        )
        .into_storage_result()?;
        cumulated_gas = cumulated_gas
            .checked_add(tx_gas_meter.get_tx_consumed_gas())
            .ok_or(namada_state::StorageError::SimpleMessage(
                "Overflow in gas",
            ))?;
        // Account gas for both inner and wrapper (if available)
        data.gas_used = cumulated_gas;
        // NOTE: the keys changed by the wrapper transaction (if any) are not
        // returned from this function
        let data = data.serialize_to_vec();
        Ok(EncodedResponseQuery {
            data,
            proof: None,
            info: Default::default(),
        })
    }
}

#[cfg(test)]
mod test {
    use borsh::BorshDeserialize;
    use borsh_ext::BorshSerializeExt;
    use namada_core::types::address;
    use namada_core::types::hash::Hash;
    use namada_core::types::storage::{BlockHeight, Key};
    use namada_sdk::queries::{
        EncodedResponseQuery, RequestCtx, RequestQuery, Router, RPC,
    };
    use namada_sdk::tendermint_rpc::{self, Error as RpcError, Response};
    use namada_state::testing::TestWlStorage;
    use namada_state::StorageWrite;
    use namada_test_utils::TestWasms;
    use namada_tx::data::decrypted::DecryptedTx;
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
            let mut wl_storage = TestWlStorage::default();

            // Initialize mock gas limit
            let max_block_gas_key =
                namada_parameters::storage::get_max_block_gas_key();
            wl_storage
                .storage
                .write(
                    &max_block_gas_key,
                    namada_core::types::encode(&20_000_000_u64),
                )
                .expect(
                    "Max block gas parameter must be initialized in storage",
                );
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
                wl_storage: &self.wl_storage,
                event_log: &self.event_log,
                vp_wasm_cache: self.vp_wasm_cache.clone(),
                tx_wasm_cache: self.tx_wasm_cache.clone(),
                storage_read_past_height_limit: None,
            };
            // TODO: this is a hack to propagate errors to the caller, we should
            // really permit error types other than [`std::io::Error`]
            if request.path == "/shell/dry_run_tx" {
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
            R: tendermint_rpc::SimpleRequest,
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
        client.wl_storage.storage.write(&key, &tx_no_op).unwrap();
        client
            .wl_storage
            .storage
            .write(&len_key, (tx_no_op.len() as u64).serialize_to_vec())
            .unwrap();

        // Request last committed epoch
        let read_epoch = RPC.shell().epoch(&client).await.unwrap();
        let current_epoch = client.wl_storage.storage.last_epoch;
        assert_eq!(current_epoch, read_epoch);

        // Request dry run tx
        let mut outer_tx =
            Tx::from_type(TxType::Decrypted(DecryptedTx::Decrypted));
        outer_tx.header.chain_id = client.wl_storage.storage.chain_id.clone();
        outer_tx.set_code(Code::from_hash(tx_hash, None));
        outer_tx.set_data(Data::new(vec![]));
        let tx_bytes = outer_tx.to_bytes();
        let result = RPC
            .shell()
            .dry_run_tx(&client, Some(tx_bytes), None, false)
            .await
            .unwrap();
        assert!(result.data.is_accepted());

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
        StorageWrite::write(&mut client.wl_storage, &balance_key, balance)?;
        // It has to be committed to be visible in a query
        client.wl_storage.commit_tx();
        client.wl_storage.commit_block().unwrap();
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
