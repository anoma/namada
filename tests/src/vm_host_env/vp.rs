use std::collections::HashSet;

use anoma_shared::ledger::gas::VpGasMeter;
use anoma_shared::ledger::storage::mockdb::MockDB;
use anoma_shared::ledger::storage::testing::TestStorage;
use anoma_shared::ledger::storage::write_log::WriteLog;
use anoma_shared::types::address::{self, Address};
use anoma_shared::types::Key;
use anoma_shared::vm;
use anoma_shared::vm::prefix_iter::PrefixIterators;
use anoma_shared::vm::{
    EnvHostSliceWrapper, EnvHostWrapper, MutEnvHostWrapper,
};

/// This module combines the native host function implementations from
/// `native_vp_host_env` with the functions exposed to the vp wasm
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
    pub gas_meter: VpGasMeter,
    pub tx_code: Vec<u8>,
    pub keys_changed: Vec<Key>,
    pub verifiers: HashSet<Address>,
    pub eval_runner: Option<native_vp_host_env::VpEval>,
}

impl Default for TestVpEnv {
    fn default() -> Self {
        let addr = address::testing::established_address_1();
        let storage = TestStorage::default();
        let write_log = WriteLog::default();
        let iterators = PrefixIterators::default();
        let gas_meter = VpGasMeter::new(0);
        let tx_code = vec![];
        let keys_changed = vec![];
        let verifiers = HashSet::default();

        // Because the `eval_runner`'s references must point to the data inside
        // the `env`, we have to initialize `env` with the other fields first,
        // and then add `eval_runner` in.
        let mut env = Self {
            addr,
            storage,
            write_log,
            iterators,
            gas_meter,
            tx_code,
            keys_changed,
            verifiers,
            eval_runner: None,
        };

        #[cfg(feature = "wasm-runtime")]
        let eval_runner = {
            let env_storage = unsafe { EnvHostWrapper::new(&env.storage) };
            let env_write_log = unsafe { EnvHostWrapper::new(&env.write_log) };
            let env_iterators =
                unsafe { MutEnvHostWrapper::new(&mut env.iterators) };
            let env_gas_meter =
                unsafe { MutEnvHostWrapper::new(&mut env.gas_meter) };
            let env_tx_code =
                unsafe { EnvHostSliceWrapper::new(&env.tx_code[..]) };
            let env_keys_changed =
                unsafe { EnvHostSliceWrapper::new(&env.keys_changed[..]) };
            let env_verifiers = unsafe { EnvHostWrapper::new(&env.verifiers) };

            anoma_shared::vm::wasm::runner::VpEval {
                address: env.addr.clone(),
                storage: env_storage,
                write_log: env_write_log,
                iterators: env_iterators,
                gas_meter: env_gas_meter,
                tx_code: env_tx_code,
                keys_changed: env_keys_changed,
                verifiers: env_verifiers,
            }
        };
        #[cfg(not(feature = "wasm-runtime"))]
        let eval_runner = native_vp_host_env::VpEval;
        env.eval_runner = Some(eval_runner);

        env
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
        keys_changed,
        verifiers,
        eval_runner,
    }: &mut TestVpEnv,
) {
    vp_host_env::ENV.with(|env| {
        *env.borrow_mut() = Some({
            vm::host_env::testing::vp_env(
                addr.clone(),
                storage,
                write_log,
                iterators,
                gas_meter,
                tx_code,
                keys_changed,
                verifiers,
                eval_runner
                    .as_ref()
                    .expect("the eval_runner should be initialized"),
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

    use anoma_shared::ledger::storage::testing::Sha256Hasher;
    use anoma_shared::vm::host_env::*;
    use anoma_shared::vm::memory::testing::NativeMemory;
    // TODO replace with `std::concat_idents` once stabilized (https://github.com/rust-lang/rust/issues/29599)
    use concat_idents::concat_idents;

    use super::*;

    #[cfg(feature = "wasm-runtime")]
    pub type VpEval =
        anoma_shared::vm::wasm::runner::VpEval<'static, MockDB, Sha256Hasher>;
    #[cfg(not(feature = "wasm-runtime"))]
    pub struct VpEval;

    thread_local! {
        pub static ENV: RefCell<Option<VpEnv<'static, NativeMemory, MockDB, Sha256Hasher, VpEval>>> = RefCell::new(None);
    }

    #[cfg(not(feature = "wasm-runtime"))]
    impl VpEvalRunner for VpEval {
        fn eval(
            &self,
            vp_code: Vec<u8>,
            input_data: Vec<u8>,
        ) -> anoma_shared::types::internal::HostEnvResult {
            unimplemented!(
                "The \"wasm-runtime\" feature must be enabled to test with \
                 the `eval` function."
            )
        }
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
    native_host_fn!(vp_eval(
            vp_code_ptr: u64,
            vp_code_len: u64,
            input_data_ptr: u64,
            input_data_len: u64,
        ) -> i64);
    native_host_fn!(vp_log_string(str_ptr: u64, str_len: u64));
}
