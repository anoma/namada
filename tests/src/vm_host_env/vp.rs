use anoma::node::vm::host_env::prefix_iter::PrefixIterators;
use anoma::node::vm::host_env::testing;
use anoma::node::vm::host_env::write_log::WriteLog;
use anoma::node::vm::memory::testing::NativeMemory;
use anoma_shared::protocol::gas::BlockGasMeter;
use anoma_shared::protocol::storage::mockdb::MockDB;
use anoma_shared::protocol::storage::testing::TestStorage;
use anoma_shared::types::address::{self, Address};

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
#[allow(dead_code)]
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

/// This module allows to test code with vp host environment functions.
/// It keeps a thread-local global `VpEnv`, which is passed to any of
/// invoked host environment functions and so it must be initialized
/// before the test.
mod native_vp_host_env {

    use std::cell::RefCell;

    use anoma::node::vm::host_env::*;
    use anoma_shared::protocol::storage::testing::Sha256Hasher;
    // TODO replace with `std::concat_idents` once stabilized (https://github.com/rust-lang/rust/issues/29599)
    use concat_idents::concat_idents;

    use super::*;

    thread_local! {
        pub static ENV: RefCell<Option<VpEnv<MockDB, NativeMemory, Sha256Hasher>>> = RefCell::new(None);
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
