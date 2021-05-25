#[cfg(any(test, feature = "testing"))]
mod testing {
    use std::collections::HashSet;

    use anoma::node::shell::gas::BlockGasMeter;
    use anoma::node::shell::storage::db::mock::MockDB;
    use anoma::node::shell::storage::testing::TestStorage;
    use anoma::node::vm::host_env::prefix_iter::PrefixIterators;
    use anoma::node::vm::host_env::testing;
    use anoma::node::vm::host_env::write_log::WriteLog;
    use anoma_shared::types::Address;

    pub mod native_tx_host_env {

        use anoma::node::shell::storage::db::mock::MockDB;
        use anoma::node::vm::host_env::*;
        use anoma::node::vm::memory::testing::NativeMemory;
        // TODO replace with `std::concat_idents` once stabilized (https://github.com/rust-lang/rust/issues/29599)
        use concat_idents::concat_idents;

        pub static mut ENV: Option<TxEnv<MockDB, NativeMemory>> = None;

        macro_rules! native_host_fn {
            // unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) ) => {
                #[no_mangle]
                extern "C" fn $fn( $($arg: $type),* ) {
                    let env = unsafe { ENV.as_ref() }.expect("Did you forget to initialize the ENV?");
                    concat_idents!(fn_name = tx, $fn {
                        fn_name( &env, $($arg),* )
                    })
                }

            };

            // non-unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) -> $ret:ty ) => {
                #[no_mangle]
                extern "C" fn $fn( $($arg: $type),* ) -> $ret {
                    let env = unsafe { ENV.as_ref() }.expect("Did you forget to initialize the ENV?");
                    concat_idents!(fn_name = tx, $fn {
                        fn_name( &env, $($arg),* )
                    })
                }

            }
        }

        native_host_fn!(_read(key_ptr: u64, key_len: u64, result_ptr: u64) -> i64);
        native_host_fn!(_has_key(key_ptr: u64, key_len: u64) -> u64);
        native_host_fn!(_write(
            key_ptr: u64,
            key_len: u64,
            val_ptr: u64,
            val_len: u64
        ));
        native_host_fn!(_delete(key_ptr: u64, key_len: u64) -> u64);
        native_host_fn!(_iter_prefix(prefix_ptr: u64, prefix_len: u64) -> u64);
        native_host_fn!(_iter_next(iter_id: u64, result_ptr: u64) -> i64);
        native_host_fn!(_insert_verifier(addr_ptr: u64, addr_len: u64));
        native_host_fn!(_update_validity_predicate(
            addr_ptr: u64,
            addr_len: u64,
            code_ptr: u64,
            code_len: u64,
        ));
        native_host_fn!(_init_account(code_ptr: u64, code_len: u64, result_ptr: u64) -> u64);
        native_host_fn!(_get_chain_id(result_ptr: u64));
        native_host_fn!(_get_block_height() -> u64);
        native_host_fn!(_get_block_hash(result_ptr: u64));
    }

    pub mod tx_host_env {
        pub use anoma_vm_env::imports::tx::*;

        pub use super::native_tx_host_env::*;
    }

    pub struct TestTxEnv {
        storage: TestStorage,
        write_log: WriteLog,
        iterators: PrefixIterators<'static, MockDB>,
        verifiers: HashSet<Address>,
        gas_meter: BlockGasMeter,
    }

    impl Default for TestTxEnv {
        fn default() -> Self {
            Self {
                storage: TestStorage::default(),
                write_log: WriteLog::default(),
                iterators: PrefixIterators::default(),
                verifiers: HashSet::default(),
                gas_meter: BlockGasMeter::default(),
            }
        }
    }

    fn init_tx_env(
        TestTxEnv {
            storage,
            write_log,
            iterators,
            verifiers,
            gas_meter,
        }: &mut TestTxEnv,
    ) {
        unsafe {
            tx_host_env::ENV = Some({
                testing::tx_env(
                    storage, write_log, iterators, verifiers, gas_meter,
                )
            });
        }
    }

    #[test]
    fn test_tx_host_env() {
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        let key = "key";
        let value = "test".to_string();
        tx_host_env::write(key, value.clone());

        let read_value: Option<String> = tx_host_env::read(key);
        assert_eq!(Some(value), read_value);
    }
}
