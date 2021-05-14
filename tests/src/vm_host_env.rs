#[cfg(any(test, feature = "testing"))]
mod testing {
    pub mod tx_host_env_mocks {
        use std::collections::HashSet;

        use anoma::node::shell::gas::BlockGasMeter;
        use anoma::node::shell::storage::db::mock::MockDB;
        use anoma::node::shell::storage::testing::TestStorage;
        use anoma::node::vm::host_env::prefix_iter::PrefixIterators;
        use anoma::node::vm::host_env::testing::mock_tx_env;
        use anoma::node::vm::host_env::write_log::WriteLog;
        use anoma::node::vm::host_env::*;
        use anoma::node::vm::memory::testing::MockMemory;
        // TODO replace with `std::concat_idents` once stabilized (https://github.com/rust-lang/rust/issues/29599)
        use concat_idents::concat_idents;
        use lazy_static::lazy_static;

        lazy_static! {
            pub static ref ENV: TxEnv<MockDB, MockMemory> = {
                let storage = TestStorage::default();
                let mut write_log = WriteLog::default();
                let mut iterators = PrefixIterators::default();
                let mut verifiers = HashSet::default();
                let mut gas_meter = BlockGasMeter::default();
                mock_tx_env(
                    &storage,
                    &mut write_log,
                    &mut iterators,
                    &mut verifiers,
                    &mut gas_meter,
                )
            };
        }

        macro_rules! mock_host_fn {
            // unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) ) => {
                #[no_mangle]
                extern "C" fn $fn( $($arg: $type),* ) {
                    concat_idents!(fn_name = tx, $fn {
                        fn_name( &ENV, $($arg),* )
                    })
                }

            };

            // non-unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) -> $ret:ty ) => {
                #[no_mangle]
                extern "C" fn $fn( $($arg: $type),* ) -> $ret {
                    concat_idents!(fn_name = tx, $fn {
                        fn_name( &ENV, $($arg),* )
                    })
                }

            }
        }

        mock_host_fn!(_read(key_ptr: u64, key_len: u64, result_ptr: u64) -> i64);
        mock_host_fn!(_has_key(key_ptr: u64, key_len: u64) -> u64);
        mock_host_fn!(_write(
            key_ptr: u64,
            key_len: u64,
            val_ptr: u64,
            val_len: u64
        ));
        mock_host_fn!(_delete(key_ptr: u64, key_len: u64) -> u64);
        mock_host_fn!(_iter_prefix(prefix_ptr: u64, prefix_len: u64) -> u64);
        mock_host_fn!(_iter_next(iter_id: u64, result_ptr: u64) -> i64);
        mock_host_fn!(_insert_verifier(addr_ptr: u64, addr_len: u64));
        mock_host_fn!(_update_validity_predicate(
            addr_ptr: u64,
            addr_len: u64,
            code_ptr: u64,
            code_len: u64,
        ));
        mock_host_fn!(_init_account(code_ptr: u64, code_len: u64, result_ptr: u64) -> u64);
        mock_host_fn!(_get_chain_id(result_ptr: u64));
        mock_host_fn!(_get_block_height() -> u64);
        mock_host_fn!(_get_block_hash(result_ptr: u64));
    }

    pub mod tx_host_env {
        pub use anoma_vm_env::imports::tx::*;

        pub use super::tx_host_env_mocks::*;
    }

    #[test]
    fn test_tx_host_env() {
        let key = "key";
        let value = "test".to_string();
        tx_host_env::write(key, &value);

        let read_value: Option<String> = tx_host_env::read(key);
        assert_eq!(Some(value), read_value);
    }
}
