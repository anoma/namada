#[cfg(test)]
mod tests {
    use anoma_shared::types::Key;
    use anoma_vm_env::tx_prelude::BorshSerialize;

    use super::tx::*;
    use super::vp::*;

    /// An example how to write a tx host environment integration test
    #[test]
    fn test_tx_host_env() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        let key = "key";
        let value = "test".to_string();
        tx_host_env::write(key, value.clone());

        let read_value: Option<String> = tx_host_env::read(key);
        assert_eq!(Some(value), read_value);
    }

    /// An example how to write a VP host environment integration test
    #[test]
    fn test_vp_host_env() {
        // The environment must be initialized first
        let mut env = TestVpEnv::default();
        init_vp_env(&mut env);

        // We can add some data to the environment
        let key_raw = "key";
        let key = Key::parse(key_raw.to_string()).unwrap();
        let value = "test".to_string();
        let value_raw = value.try_to_vec().unwrap();
        env.write_log.write(&key, value_raw);

        let read_pre_value: Option<String> = vp_host_env::read_pre(key_raw);
        assert_eq!(None, read_pre_value);
        let read_post_value: Option<String> = vp_host_env::read_post(key_raw);
        assert_eq!(Some(value), read_post_value);
        // let read_post_value = env.write_log.read(&key);
        // println!("A {:?}", read_post_value);
    }
}

pub mod tx {
    use std::collections::HashSet;

    use anoma::node::shell::gas::BlockGasMeter;
    use anoma::node::shell::storage::db::mock::MockDB;
    use anoma::node::shell::storage::testing::TestStorage;
    use anoma::node::vm::host_env::prefix_iter::PrefixIterators;
    use anoma::node::vm::host_env::testing;
    use anoma::node::vm::host_env::write_log::WriteLog;
    use anoma::node::vm::memory::testing::NativeMemory;
    use anoma_shared::types::Address;

    /// This module allows to test code with tx host environment functions.
    /// It keeps a thread-local global `TxEnv`, which is passed to any of
    /// invoked host environment functions and so it must be initialized
    /// before the test.
    pub mod native_tx_host_env {

        use std::cell::RefCell;

        use anoma::node::vm::host_env::*;
        // TODO replace with `std::concat_idents` once stabilized (https://github.com/rust-lang/rust/issues/29599)
        use concat_idents::concat_idents;

        use super::*;

        thread_local! {
            pub static ENV: RefCell<Option<TxEnv<MockDB, NativeMemory>>> = RefCell::new(None);
        }

        /// A helper macro to create implementations of the host environment
        /// functions exported to wasm, which uses the environment from the
        /// `ENV` variable.
        macro_rules! native_host_fn {
            // unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) ) => {
                concat_idents!(extern_fn_name = anoma, _, $fn {
                    #[no_mangle]
                    extern "C" fn extern_fn_name( $($arg: $type),* ) {
                        ENV.with(|env| {
                            let env = env.borrow_mut();
                            let env = env.as_ref().expect("Did you forget to initialize the ENV?");

                            $fn( &env, $($arg),* )
                        })
                    }
                });
            };

            // non-unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) -> $ret:ty ) => {
                concat_idents!(extern_fn_name = anoma, _, $fn {
                    #[no_mangle]
                    extern "C" fn extern_fn_name( $($arg: $type),* ) -> $ret {
                        ENV.with(|env| {
                            let env = env.borrow_mut();
                            let env = env.as_ref().expect("Did you forget to initialize the ENV?");

                            $fn( &env, $($arg),* )
                        })
                    }
                });
            }
        }

        // Implement all the exported functions from
        // [`anoma_vm_env::imports::tx`] `extern "C"` section.
        native_host_fn!(tx_read(key_ptr: u64, key_len: u64, result_ptr: u64) -> i64);
        native_host_fn!(tx_has_key(key_ptr: u64, key_len: u64) -> i64);
        native_host_fn!(tx_write(
            key_ptr: u64,
            key_len: u64,
            val_ptr: u64,
            val_len: u64
        ));
        native_host_fn!(tx_delete(key_ptr: u64, key_len: u64));
        native_host_fn!(tx_iter_prefix(prefix_ptr: u64, prefix_len: u64) -> u64);
        native_host_fn!(tx_iter_next(iter_id: u64, result_ptr: u64) -> i64);
        native_host_fn!(tx_insert_verifier(addr_ptr: u64, addr_len: u64));
        native_host_fn!(tx_update_validity_predicate(
            addr_ptr: u64,
            addr_len: u64,
            code_ptr: u64,
            code_len: u64,
        ));
        native_host_fn!(tx_init_account(code_ptr: u64, code_len: u64, result_ptr: u64) -> u64);
        native_host_fn!(tx_get_chain_id(result_ptr: u64));
        native_host_fn!(tx_get_block_height() -> u64);
        native_host_fn!(tx_get_block_hash(result_ptr: u64));
        native_host_fn!(tx_log_string(str_ptr: u64, str_len: u64));
    }

    /// This module combines the native host function implementations from
    /// [`native_tx_host_env`] above with the functions exposed to the tx wasm
    /// that will call to the native functions, instead of interfacing via a
    /// wasm runtime. It can be used for host environment integration tests.
    pub mod tx_host_env {
        pub use anoma_vm_env::imports::tx::*;

        pub use super::native_tx_host_env::*;
    }

    /// Host environment structures required for transactions.
    pub struct TestTxEnv {
        pub storage: TestStorage,
        pub write_log: WriteLog,
        pub iterators: PrefixIterators<'static, MockDB>,
        pub verifiers: HashSet<Address>,
        pub gas_meter: BlockGasMeter,
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

    /// Initialize the host environment inside the [`tx_host_env`] module.
    pub fn init_tx_env(
        TestTxEnv {
            storage,
            write_log,
            iterators,
            verifiers,
            gas_meter,
        }: &mut TestTxEnv,
    ) {
        tx_host_env::ENV.with(|env| {
            *env.borrow_mut() = Some({
                testing::tx_env(
                    storage, write_log, iterators, verifiers, gas_meter,
                )
            })
        });
    }
}

pub mod vp {
    use anoma::node::shell::gas::BlockGasMeter;
    use anoma::node::shell::storage::db::mock::MockDB;
    use anoma::node::shell::storage::testing::TestStorage;
    use anoma::node::vm::host_env::prefix_iter::PrefixIterators;
    use anoma::node::vm::host_env::testing;
    use anoma::node::vm::host_env::write_log::WriteLog;
    use anoma::node::vm::memory::testing::NativeMemory;
    use anoma_shared::types::address::{self, Address};

    /// This module allows to test code with vp host environment functions.
    /// It keeps a thread-local global `VpEnv`, which is passed to any of
    /// invoked host environment functions and so it must be initialized
    /// before the test.
    pub mod native_vp_host_env {

        use std::cell::RefCell;

        use anoma::node::vm::host_env::*;
        // TODO replace with `std::concat_idents` once stabilized (https://github.com/rust-lang/rust/issues/29599)
        use concat_idents::concat_idents;

        use super::*;

        thread_local! {
            pub static ENV: RefCell<Option<VpEnv<MockDB, NativeMemory>>> = RefCell::new(None);
        }

        /// A helper macro to create implementations of the host environment
        /// functions exported to wasm, which uses the environment from the
        /// `ENV` variable.
        macro_rules! native_host_fn {
            // unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) ) => {
                concat_idents!(extern_fn_name = anoma, _, $fn {
                    #[no_mangle]
                    extern "C" fn extern_fn_name( $($arg: $type),* ) {
                        ENV.with(|env| {
                            let env = env.borrow_mut();
                            let env = env.as_ref().expect("Did you forget to
    initialize the ENV?");

                            $fn( &env, $($arg),* )
                        })
                    }
                });
            };

            // non-unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) -> $ret:ty ) => {
                concat_idents!(extern_fn_name = anoma, _, $fn {
                    #[no_mangle]
                    extern "C" fn extern_fn_name( $($arg: $type),* ) -> $ret {
                        ENV.with(|env| {
                            let env = env.borrow_mut();
                            let env = env.as_ref().expect("Did you forget to
    initialize the ENV?");

                            $fn( &env, $($arg),* )
                        })
                    }
                });
            }
        }

        // Implement all the exported functions from
        // [`anoma_vm_env::imports::vp`] `extern "C"` section.
        native_host_fn!(vp_read_pre(key_ptr: u64, key_len: u64, result_ptr: u64) -> i64);
        native_host_fn!(vp_read_post(key_ptr: u64, key_len: u64, result_ptr: u64) -> i64);
        native_host_fn!(vp_has_key_pre(key_ptr: u64, key_len: u64) -> i64);
        native_host_fn!(vp_has_key_post(key_ptr: u64, key_len: u64) -> i64);
        native_host_fn!(vp_iter_prefix(prefix_ptr: u64, prefix_len: u64) -> u64);
        native_host_fn!(vp_iter_pre_next(iter_id: u64, result_ptr: u64) ->
i64);
        native_host_fn!(vp_iter_post_next(iter_id: u64, result_ptr: u64) -> i64);
        native_host_fn!(vp_get_chain_id(result_ptr: u64));
        native_host_fn!(vp_get_block_height() -> u64);
        native_host_fn!(vp_get_block_hash(result_ptr: u64));
        native_host_fn!(vp_verify_tx_signature(
            pk_ptr: u64,
            pk_len: u64,
            data_ptr: u64,
            data_len: u64,
            sig_ptr: u64,
            sig_len: u64,
        ) -> i64);
        native_host_fn!(vp_log_string(str_ptr: u64, str_len: u64));
    }

    /// This module combines the native host function implementations from
    /// [`native_vp_host_env`] above with the functions exposed to the vp wasm
    /// that will call to the native functions, instead of interfacing via a
    /// wasm runtime. It can be used for host environment integration tests.
    pub mod vp_host_env {
        pub use anoma_vm_env::imports::vp::*;

        pub use super::native_vp_host_env::*;
    }

    /// Host environment structures required for transactions.
    pub struct TestVpEnv {
        pub addr: Address,
        pub storage: TestStorage,
        pub write_log: WriteLog,
        pub iterators: PrefixIterators<'static, MockDB>,
        pub gas_meter: BlockGasMeter,
        pub tx_code: Vec<u8>,
    }

    impl Default for TestVpEnv {
        fn default() -> Self {
            Self {
                addr: address::testing::established_address_1(),
                storage: TestStorage::default(),
                write_log: WriteLog::default(),
                iterators: PrefixIterators::default(),
                gas_meter: BlockGasMeter::default(),
                tx_code: vec![],
            }
        }
    }

    /// Initialize the host environment inside the [`vp_host_env`] module.
    pub fn init_vp_env(
        TestVpEnv {
            addr,
            storage,
            write_log,
            iterators,
            gas_meter,
            tx_code,
        }: &mut TestVpEnv,
    ) {
        vp_host_env::ENV.with(|env| {
            *env.borrow_mut() = Some({
                testing::vp_env(
                    addr.clone(),
                    storage,
                    write_log,
                    iterators,
                    gas_meter,
                    tx_code,
                )
            })
        });
    }
}
