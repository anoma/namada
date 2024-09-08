//! Utils for testing with transaction code with `Ctx` and/or `TxEnv`.

#![allow(missing_docs)]
#![allow(clippy::print_stdout, clippy::arithmetic_side_effects)]

use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use namada_core::address::Address;
use namada_core::hash::Hash;
use namada_gas::TxGasMeter;
use namada_state::mockdb::MockDB;
use namada_state::prefix_iter::PrefixIterators;
use namada_state::testing::TestState;
use namada_state::{Key, TxIndex};
use namada_tx::data::TxSentinel;
pub use namada_tx::data::TxType;
pub use namada_tx::*;
use namada_vm::wasm::run::Error;
use namada_vm::wasm::{self, wasmer, TxCache, VpCache};
use namada_vm::WasmCacheRwAccess;
use tempfile::TempDir;

use crate::ctx::Ctx;

/// Tx execution context provides access to host env functions
static mut CTX: Ctx = unsafe { Ctx::new() };

/// Tx execution context provides access to host env functions
pub fn ctx() -> &'static mut Ctx {
    unsafe { &mut *std::ptr::addr_of_mut!(CTX) }
}

/// Host environment structures required for transactions.
#[derive(Debug)]
pub struct TestTxEnv {
    pub state: TestState,
    pub iterators: PrefixIterators<'static, MockDB>,
    pub verifiers: BTreeSet<Address>,
    pub gas_meter: RefCell<TxGasMeter>,
    pub sentinel: RefCell<TxSentinel>,
    pub tx_index: TxIndex,
    pub result_buffer: Option<Vec<u8>>,
    pub yielded_value: Option<Vec<u8>>,
    pub vp_wasm_cache: VpCache<WasmCacheRwAccess>,
    pub vp_cache_dir: TempDir,
    pub tx_wasm_cache: TxCache<WasmCacheRwAccess>,
    pub tx_cache_dir: TempDir,
    pub batched_tx: BatchedTx,
    pub wasmer_store: Rc<RefCell<wasmer::Store>>,
}
impl Default for TestTxEnv {
    fn default() -> Self {
        let (vp_wasm_cache, vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();
        let (tx_wasm_cache, tx_cache_dir) =
            wasm::compilation_cache::common::testing::cache();
        let state = TestState::default();
        let mut tx = Tx::from_type(TxType::Raw);
        tx.header.chain_id = state.in_mem().chain_id.clone();
        tx.push_default_inner_tx();
        let batched_tx = tx.batch_first_tx();

        let wasmer_store = Rc::new(RefCell::new(
            wasm::compilation_cache::common::testing::store(),
        ));

        Self {
            state,
            iterators: PrefixIterators::default(),
            gas_meter: RefCell::new(TxGasMeter::new(1_000_000_000_000)),
            sentinel: RefCell::new(TxSentinel::default()),
            tx_index: TxIndex::default(),
            verifiers: BTreeSet::default(),
            result_buffer: None,
            yielded_value: None,
            vp_wasm_cache,
            vp_cache_dir,
            tx_wasm_cache,
            tx_cache_dir,
            batched_tx,
            wasmer_store,
        }
    }
}

impl TestTxEnv {
    pub fn all_touched_storage_keys(&self) -> BTreeSet<Key> {
        self.state.write_log().get_keys()
    }

    pub fn get_verifiers(&self) -> BTreeSet<Address> {
        self.state
            .write_log()
            .verifiers_and_changed_keys(&self.verifiers)
            .0
    }

    pub fn store_wasm_code(&mut self, code: Vec<u8>) {
        let hash = Hash::sha256(&code);
        let key = Key::wasm_code(&hash);
        self.state.db_write(&key, code).unwrap();
    }

    /// Fake accounts' existence by initializing their VP storage.
    /// This is needed for accounts that are being modified by a tx test to
    /// pass account existence check in `tx_write` function. Only established
    /// addresses ([`Address::Established`]) have their VP storage initialized,
    /// as other types of accounts should not have wasm VPs in storage in any
    /// case.
    pub fn spawn_accounts(
        &mut self,
        addresses: impl IntoIterator<Item = impl Borrow<Address>>,
    ) {
        for address in addresses {
            if matches!(
                address.borrow(),
                Address::Internal(_) | Address::Implicit(_)
            ) {
                continue;
            }
            let key = Key::validity_predicate(address.borrow());
            let vp_code = vec![];
            self.state
                .db_write(&key, vp_code)
                .expect("Unable to write VP");
        }
    }

    /// Commit the genesis state. Typically, you'll want to call this after
    /// setting up the initial state, before running a transaction.
    pub fn commit_genesis(&mut self) {
        self.state.commit_block().unwrap();
    }

    pub fn commit_tx_and_block(&mut self) {
        self.state.commit_tx_batch();
        self.state
            .commit_block()
            .map_err(|err| println!("{:?}", err))
            .ok();
        self.iterators = PrefixIterators::default();
        self.verifiers = BTreeSet::default();
    }

    /// Apply the tx changes to the write log.
    pub fn execute_tx(&mut self) -> Result<(), Error> {
        wasm::run::tx(
            &mut self.state,
            &self.gas_meter,
            &self.tx_index,
            &self.batched_tx.tx,
            &self.batched_tx.cmt,
            &mut self.vp_wasm_cache,
            &mut self.tx_wasm_cache,
        )
        .and(Ok(()))
    }
}

/// This module allows to test code with tx host environment functions.
/// It keeps a thread-local global `TxEnv`, which is passed to any of
/// invoked host environment functions and so it must be initialized
/// before the test.
pub mod native_tx_env {
    use std::pin::Pin;

    // TODO replace with `std::concat_idents` once stabilized (https://github.com/rust-lang/rust/issues/29599)
    use concat_idents::concat_idents;
    use namada_vm::host_env::*;

    use super::*;

    thread_local! {
        /// A [`TestTxEnv`] that can be used for tx host env functions calls
        /// that implements the WASM host environment in native environment.
        pub static ENV: RefCell<Option<Pin<Box<TestTxEnv>>>> =
            const { RefCell::new(None) };
    }

    /// Initialize the tx host environment in [`ENV`]. This will be used in the
    /// host env function calls via macro `native_host_fn!`.
    pub fn init() {
        ENV.with(|env| {
            let test_env = TestTxEnv::default();
            *env.borrow_mut() = Some(Box::pin(test_env));
        });
    }

    /// Set the tx host environment in [`ENV`] from the given [`TestTxEnv`].
    /// This will be used in the host env function calls via
    /// macro `native_host_fn!`.
    pub fn set(test_env: TestTxEnv) {
        ENV.with(|env| {
            *env.borrow_mut() = Some(Box::pin(test_env));
        });
    }

    /// Mutably borrow the [`TestTxEnv`] from [`ENV`]. The [`ENV`] must be
    /// initialized.
    pub fn with<T>(f: impl Fn(&mut TestTxEnv) -> T) -> T {
        ENV.with(|env| {
            let mut env = env.borrow_mut();
            let mut env = env
                .as_mut()
                .expect(
                    "Did you forget to initialize the ENV? (e.g. call to \
                     `tx_env::init()`)",
                )
                .as_mut();
            f(&mut env)
        })
    }

    /// Take the [`TestTxEnv`] out of [`ENV`]. The [`ENV`] must be initialized.
    pub fn take() -> TestTxEnv {
        ENV.with(|env| {
            let mut env = env.borrow_mut();
            let env = env.take().expect(
                "Did you forget to initialize the ENV? (e.g. call to \
                 `tx_env::init()`)",
            );
            let env = Pin::into_inner(env);
            *env
        })
    }

    pub fn commit_tx_and_block() {
        with(|env| env.commit_tx_and_block())
    }

    /// A helper macro to create implementations of the host environment
    /// functions exported to wasm, which uses the environment from the
    /// `ENV` variable.
    macro_rules! native_host_fn {
            // unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) ) => {
                concat_idents!(extern_fn_name = namada, _, $fn {
                    #[no_mangle]
                    extern "C" fn extern_fn_name( $($arg: $type),* ) {
                        with(|TestTxEnv {
                                state,
                                iterators,
                                verifiers,
                                gas_meter,
                                sentinel,
                                result_buffer,
                                yielded_value,
                                tx_index,
                                vp_wasm_cache,
                                vp_cache_dir: _,
                                tx_wasm_cache,
                                tx_cache_dir: _,
                                batched_tx,
                                wasmer_store: _,
                            }: &mut TestTxEnv| {

                            let mut tx_env = namada_vm::host_env::testing::tx_env(
                                state,
                                iterators,
                                verifiers,
                                gas_meter,
                                sentinel,
                                &batched_tx.tx,
                                &batched_tx.cmt,
                                tx_index,
                                result_buffer,
                                yielded_value,
                                vp_wasm_cache,
                                tx_wasm_cache,
                            );

                            // Call the `host_env` function and unwrap any
                            // runtime errors
                            $fn( &mut tx_env, $($arg),* ).unwrap()
                        })
                    }
                });
            };

            // non-unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) -> $ret:ty ) => {
                concat_idents!(extern_fn_name = namada, _, $fn {
                    #[no_mangle]
                    extern "C" fn extern_fn_name( $($arg: $type),* ) -> $ret {
                        with(|TestTxEnv {
                                tx_index,
                                state,
                                iterators,
                                verifiers,
                                gas_meter,
                                sentinel,
                                result_buffer,
                                yielded_value,
                                vp_wasm_cache,
                                vp_cache_dir: _,
                                tx_wasm_cache,
                                tx_cache_dir: _,
                                batched_tx,
                                wasmer_store: _,
                            }: &mut TestTxEnv| {

                            let mut tx_env = namada_vm::host_env::testing::tx_env(
                                state,
                                iterators,
                                verifiers,
                                gas_meter,
                                sentinel,
                                &batched_tx.tx,
                                &batched_tx.cmt,
                                tx_index,
                                result_buffer,
                                yielded_value,
                                vp_wasm_cache,
                                tx_wasm_cache,
                            );

                            // Call the `host_env` function and unwrap any
                            // runtime errors
                            $fn( &mut tx_env, $($arg),* ).unwrap()
                        })
                    }
                });
            };

            // unit, non-result, return type
            ( "non-result", $fn:ident ( $($arg:ident : $type:ty),* $(,)?) ) => {
                concat_idents!(extern_fn_name = namada, _, $fn {
                    #[no_mangle]
                    extern "C" fn extern_fn_name( $($arg: $type),* ) {
                        with(|TestTxEnv {
                                state,
                                iterators,
                                verifiers,
                                gas_meter,
                                sentinel,
                                result_buffer,
                                yielded_value,
                                tx_index,
                                vp_wasm_cache,
                                vp_cache_dir: _,
                                tx_wasm_cache,
                                tx_cache_dir: _,
                                batched_tx,
                                wasmer_store: _,
                            }: &mut TestTxEnv| {

                            let mut tx_env = namada_vm::host_env::testing::tx_env(
                                state,
                                iterators,
                                verifiers,
                                gas_meter,
                                sentinel,
                                &batched_tx.tx,
                                &batched_tx.cmt,
                                tx_index,
                                result_buffer,
                                yielded_value,
                                vp_wasm_cache,
                                tx_wasm_cache,
                            );

                            // Call the `host_env` function
                            $fn( &mut tx_env, $($arg),* )
                        })
                    }
                });
            };
        }

    // Implement all the exported functions from
    // [`namada_vm_env::imports::tx`] `extern "C"` section.
    native_host_fn!(tx_read(key_ptr: u64, key_len: u64) -> i64);
    native_host_fn!(tx_read_temp(key_ptr: u64, key_len: u64) -> i64);
    native_host_fn!(tx_result_buffer(result_ptr: u64));
    native_host_fn!(tx_has_key(key_ptr: u64, key_len: u64) -> i64);
    native_host_fn!(tx_write(
        key_ptr: u64,
        key_len: u64,
        val_ptr: u64,
        val_len: u64
    ));
    native_host_fn!(tx_write_temp(
        key_ptr: u64,
        key_len: u64,
        val_ptr: u64,
        val_len: u64
    ));
    native_host_fn!(tx_delete(key_ptr: u64, key_len: u64));
    native_host_fn!(tx_iter_prefix(prefix_ptr: u64, prefix_len: u64) -> u64);
    native_host_fn!(tx_iter_next(iter_id: u64) -> i64);
    native_host_fn!(tx_insert_verifier(addr_ptr: u64, addr_len: u64));
    native_host_fn!(tx_update_validity_predicate(
        addr_ptr: u64,
        addr_len: u64,
        code_hash_ptr: u64,
        code_hash_len: u64,
        code_tag_ptr: u64,
        code_tag_len: u64,
    ));
    native_host_fn!(tx_init_account(
        code_hash_ptr: u64,
        code_hash_len: u64,
        code_tag_ptr: u64,
        code_tag_len: u64,
        entropy_source_ptr: u64,
        entropy_source_len: u64,
        result_ptr: u64
    ));
    native_host_fn!(tx_emit_event(event_ptr: u64, event_len: u64));
    native_host_fn!(tx_get_events(event_type_ptr: u64, event_type_len: u64) -> i64);
    native_host_fn!(tx_get_chain_id(result_ptr: u64));
    native_host_fn!(tx_get_block_height() -> u64);
    native_host_fn!(tx_get_tx_index() -> u32);
    native_host_fn!(tx_get_block_header(height: u64) -> i64);
    native_host_fn!(tx_get_block_epoch() -> u64);
    native_host_fn!(tx_get_pred_epochs() -> i64);
    native_host_fn!(tx_get_native_token(result_ptr: u64));
    native_host_fn!(tx_log_string(str_ptr: u64, str_len: u64));
    native_host_fn!(tx_charge_gas(used_gas: u64));
    native_host_fn!("non-result", tx_set_commitment_sentinel());
    native_host_fn!(tx_verify_tx_section_signature(
        hash_list_ptr: u64,
        hash_list_len: u64,
        public_keys_map_ptr: u64,
        public_keys_map_len: u64,
        threshold: u8,
    ) -> i64);
    native_host_fn!(tx_yield_value(
        buf_ptr: u64,
        buf_len: u64,
    ));
}

#[cfg(test)]
mod tests {
    use namada_core::hash::Sha256Hasher;
    use namada_state::{Key as StorageKey, StorageWrite};
    use namada_vm::host_env::{self, TxVmEnv};
    use namada_vm::memory::VmMemory;
    use proptest::prelude::*;
    use test_log::test;

    use super::*;

    #[derive(Debug)]
    struct TestSetup {
        write_to_memory: bool,
        write_to_wl: bool,
        write_to_storage: bool,
        key: StorageKey,
        key_memory_ptr: u64,
        read_buffer_memory_ptr: u64,
        val: Vec<u8>,
        val_memory_ptr: u64,
    }

    impl TestSetup {
        fn key_bytes(&self) -> Vec<u8> {
            self.key.to_string().as_bytes().to_vec()
        }

        fn key_len(&self) -> u64 {
            self.key_bytes().len() as _
        }

        fn val_len(&self) -> u64 {
            self.val.len() as _
        }
    }

    proptest! {
        #[test]
        fn test_tx_read_cannot_panic(
            setup in arb_test_setup()
        ) {
            test_tx_read_cannot_panic_aux(setup)
        }
    }

    fn test_tx_read_cannot_panic_aux(setup: TestSetup) {
        // dbg!(&setup);

        let mut test_env = TestTxEnv::default();
        let mut tx_env = setup_host_env(&setup, &mut test_env);

        // Can fail, but must not panic
        let _res = host_env::tx_read(
            &mut tx_env,
            setup.key_memory_ptr,
            setup.key_len(),
        );
        let _res = host_env::tx_result_buffer(
            &mut tx_env,
            setup.read_buffer_memory_ptr,
        );
    }

    proptest! {
        #[test]
        fn test_tx_charge_gas_cannot_panic(
            setup in arb_test_setup(),
            gas in arb_u64(),
        ) {
            test_tx_charge_gas_cannot_panic_aux(setup, gas)
        }
    }

    fn test_tx_charge_gas_cannot_panic_aux(setup: TestSetup, gas: u64) {
        let mut test_env = TestTxEnv::default();
        let mut tx_env = setup_host_env(&setup, &mut test_env);

        // Can fail, but must not panic
        let _res = host_env::tx_charge_gas(&mut tx_env, gas);
    }

    proptest! {
        #[test]
        fn test_tx_has_key_cannot_panic(
            setup in arb_test_setup(),
        ) {
            test_tx_has_key_cannot_panic_aux(setup)
        }
    }

    fn test_tx_has_key_cannot_panic_aux(setup: TestSetup) {
        // dbg!(&setup);

        let mut test_env = TestTxEnv::default();
        let mut tx_env = setup_host_env(&setup, &mut test_env);

        // Can fail, but must not panic
        let _res = host_env::tx_has_key(
            &mut tx_env,
            setup.key_memory_ptr,
            setup.key_len(),
        );
    }

    proptest! {
        #[test]
        fn test_tx_write_cannot_panic(
            setup in arb_test_setup(),
        ) {
            test_tx_write_cannot_panic_aux(setup)
        }
    }

    fn test_tx_write_cannot_panic_aux(setup: TestSetup) {
        // dbg!(&setup);

        let mut test_env = TestTxEnv::default();
        let mut tx_env = setup_host_env(&setup, &mut test_env);

        // Can fail, but must not panic
        let _res = host_env::tx_write(
            &mut tx_env,
            setup.key_memory_ptr,
            setup.key_len(),
            setup.val_memory_ptr,
            setup.val_len(),
        );
        let _res = host_env::tx_write_temp(
            &mut tx_env,
            setup.key_memory_ptr,
            setup.key_len(),
            setup.val_memory_ptr,
            setup.val_len(),
        );
    }

    proptest! {
        #[test]
        fn test_tx_delete_cannot_panic(
            setup in arb_test_setup(),
        ) {
            test_tx_delete_cannot_panic_aux(setup)
        }
    }

    fn test_tx_delete_cannot_panic_aux(setup: TestSetup) {
        // dbg!(&setup);

        let mut test_env = TestTxEnv::default();
        let mut tx_env = setup_host_env(&setup, &mut test_env);

        // Can fail, but must not panic
        let _res = host_env::tx_delete(
            &mut tx_env,
            setup.key_memory_ptr,
            setup.key_len(),
        );
    }

    proptest! {
        #[test]
        fn test_tx_iter_prefix_cannot_panic(
            setup in arb_test_setup(),
        ) {
            test_tx_iter_prefix_cannot_panic_aux(setup)
        }
    }

    fn test_tx_iter_prefix_cannot_panic_aux(setup: TestSetup) {
        // dbg!(&setup);

        let mut test_env = TestTxEnv::default();
        let mut tx_env = setup_host_env(&setup, &mut test_env);

        // Can fail, but must not panic
        let _res = host_env::tx_iter_prefix(
            &mut tx_env,
            setup.key_memory_ptr,
            setup.key_len(),
        );
        let _res = host_env::tx_iter_next(
            &mut tx_env,
            // This field is not used for anything else in this test
            setup.val_memory_ptr,
        );
    }

    fn setup_host_env(
        setup: &TestSetup,
        test_env: &mut TestTxEnv,
    ) -> TxVmEnv<
        wasm::memory::WasmMemory,
        MockDB,
        Sha256Hasher,
        WasmCacheRwAccess,
    > {
        if setup.write_to_storage {
            // Write the key-val to storage which may affect `tx_read` execution
            // path
            let _res = test_env.state.write_bytes(&setup.key, &setup.val);
        }
        if setup.write_to_wl {
            // Write the key-val to write log which may affect `tx_read`
            // execution path
            let _res = test_env
                .state
                .write_log_mut()
                .write(&setup.key, setup.val.clone());
        }

        let TestTxEnv {
            state,
            iterators,
            verifiers,
            gas_meter,
            sentinel,
            result_buffer,
            yielded_value,
            tx_index,
            vp_wasm_cache,
            vp_cache_dir: _,
            tx_wasm_cache,
            tx_cache_dir: _,
            batched_tx,
            wasmer_store,
        } = test_env;

        let mut tx_env = host_env::testing::tx_env_with_wasm_memory(
            state,
            iterators,
            verifiers,
            gas_meter,
            sentinel,
            &batched_tx.tx,
            &batched_tx.cmt,
            tx_index,
            result_buffer,
            yielded_value,
            wasmer_store.clone(),
            vp_wasm_cache,
            tx_wasm_cache,
        );

        if setup.write_to_memory {
            let key_bytes = setup.key_bytes();
            // Write the key-val to memory which may affect `tx_read` execution
            // path. Can fail, but must not panic
            let _res =
                tx_env.memory.write_bytes(setup.key_memory_ptr, key_bytes);
        }

        tx_env
    }

    fn arb_test_setup() -> impl Strategy<Value = TestSetup> {
        (
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            namada_state::testing::arb_key(),
            arb_u64(),
            arb_u64(),
            any::<Vec<u8>>(),
            arb_u64(),
        )
            .prop_map(
                |(
                    write_to_memory,
                    write_to_wl,
                    write_to_storage,
                    key,
                    key_memory_ptr,
                    read_buffer_memory_ptr,
                    val,
                    val_memory_ptr,
                )| TestSetup {
                    write_to_memory,
                    write_to_wl,
                    write_to_storage,
                    key,
                    key_memory_ptr,
                    read_buffer_memory_ptr,
                    val,
                    val_memory_ptr,
                },
            )
    }

    fn arb_u64() -> impl Strategy<Value = u64> {
        prop_oneof![
            5 => Just(u64::MIN),
            5 => Just(u64::MIN + 1),
            5 => u64::MIN + 2..=u64::from(u32::MAX),
            1 => Just(u64::MAX),
            1 => Just(u64::MAX - 1),
            1 => u64::from(u32::MAX) + 1..u64::MAX - 1,
        ]
    }
}
