//! The wasm host environment.
//!
//! Here, we expose the host functions into wasm's
//! imports, so they can be called from inside the wasm.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use wasmer::{
    Function, HostEnvInitError, ImportObject, Instance, Memory, Store,
    WasmerEnv,
};

use crate::gossip::mm::MmHost;
use crate::ledger::gas::{BlockGasMeter, VpGasMeter};
use crate::ledger::storage::write_log::WriteLog;
use crate::ledger::storage::{self, Storage, StorageHasher};
use crate::types::Address;
use crate::vm::host_env::{
    FilterEnv, MatchmakerEnv, TxEnv, VpEnv, VpEvalRunner,
};
use crate::vm::prefix_iter::PrefixIterators;
use crate::vm::wasm::memory::WasmMemory;
use crate::vm::{
    host_env, EnvHostSliceWrapper, EnvHostWrapper, MutEnvHostWrapper,
};

impl<DB, H> WasmerEnv for TxEnv<'_, WasmMemory, DB, H>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

impl<DB, H, EVAL> WasmerEnv for VpEnv<'_, WasmMemory, DB, H, EVAL>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

impl<MM> WasmerEnv for MatchmakerEnv<WasmMemory, MM>
where
    MM: MmHost,
{
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

impl WasmerEnv for FilterEnv<WasmMemory> {
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// transaction code
pub fn prepare_tx_imports<DB, H>(
    wasm_store: &Store,
    storage: EnvHostWrapper<'static, &'static Storage<DB, H>>,
    write_log: MutEnvHostWrapper<'static, &WriteLog>,
    iterators: MutEnvHostWrapper<'static, &PrefixIterators<'static, DB>>,
    verifiers: MutEnvHostWrapper<'static, &HashSet<Address>>,
    gas_meter: MutEnvHostWrapper<'static, &BlockGasMeter>,
    initial_memory: Memory,
) -> ImportObject
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let env = TxEnv {
        memory: WasmMemory::default(),
        storage,
        write_log,
        iterators,
        verifiers,
        gas_meter,
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "gas" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_charge_gas),
            "anoma_tx_read" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_read),
            "anoma_tx_has_key" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_has_key),
            "anoma_tx_write" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_write),
            "anoma_tx_delete" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_delete),
            "anoma_tx_iter_prefix" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_iter_prefix),
            "anoma_tx_iter_next" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_iter_next),
            "anoma_tx_insert_verifier" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_insert_verifier),
            "anoma_tx_update_validity_predicate" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_update_validity_predicate),
            "anoma_tx_init_account" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_init_account),
            "anoma_tx_get_chain_id" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_get_chain_id),
            "anoma_tx_get_block_height" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_get_block_height),
            "anoma_tx_get_block_hash" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_get_block_hash),
            "anoma_tx_log_string" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_log_string),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// validity predicate code
#[allow(clippy::too_many_arguments)]
pub fn prepare_vp_env<DB, H, EVAL>(
    wasm_store: &Store,
    addr: Address,
    storage: EnvHostWrapper<'static, &'static Storage<DB, H>>,
    write_log: EnvHostWrapper<'static, &WriteLog>,
    iterators: MutEnvHostWrapper<'static, &PrefixIterators<'static, DB>>,
    gas_meter: MutEnvHostWrapper<'static, &VpGasMeter>,
    tx_code: EnvHostSliceWrapper<'static, &[u8]>,
    initial_memory: Memory,
    eval_runner: EnvHostWrapper<'static, &'static EVAL>,
) -> ImportObject
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    let env = VpEnv {
        memory: WasmMemory::default(),
        address: addr,
        storage,
        write_log,
        iterators,
        gas_meter,
        tx_code,
        eval_runner,
    };
    prepare_vp_imports(wasm_store, initial_memory, &env)
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// validity predicate code
pub fn prepare_vp_imports<DB, H, EVAL>(
    wasm_store: &Store,
    initial_memory: Memory,
    env: &VpEnv<'static, WasmMemory, DB, H, EVAL>,
) -> ImportObject
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "gas" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_charge_gas),
            "anoma_vp_read_pre" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_read_pre),
            "anoma_vp_read_post" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_read_post),
            "anoma_vp_has_key_pre" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_has_key_pre),
            "anoma_vp_has_key_post" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_has_key_post),
            "anoma_vp_iter_prefix" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_iter_prefix),
            "anoma_vp_iter_pre_next" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_iter_pre_next),
            "anoma_vp_iter_post_next" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_iter_post_next),
            "anoma_vp_get_chain_id" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_get_chain_id),
            "anoma_vp_get_block_height" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_get_block_height),
            "anoma_vp_get_block_hash" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_get_block_hash),
            "anoma_vp_verify_tx_signature" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_verify_tx_signature),
            "anoma_vp_eval" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_eval),
            "anoma_vp_log_string" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_log_string),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// matchmaker code
pub fn prepare_mm_imports<MM>(
    wasm_store: &Store,
    initial_memory: Memory,
    mm: Arc<Mutex<MM>>,
) -> ImportObject
where
    MM: 'static + MmHost,
{
    let env = MatchmakerEnv {
        memory: WasmMemory::default(),
        mm,
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "anoma_mm_send_match" => Function::new_native_with_env(wasm_store, env.clone(), host_env::mm_send_match),
            "anoma_mm_update_data" => Function::new_native_with_env(wasm_store, env.clone(), host_env::mm_update_data),
            "anoma_mm_remove_intents" => Function::new_native_with_env(wasm_store, env.clone(), host_env::mm_remove_intents),
            "anoma_mm_log_string" => Function::new_native_with_env(wasm_store, env, host_env::mm_log_string),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// filter code
pub fn prepare_mm_filter_imports(
    wasm_store: &Store,
    initial_memory: Memory,
) -> ImportObject {
    let env = FilterEnv {
        memory: WasmMemory::default(),
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "anoma_filter_log_string" => Function::new_native_with_env(wasm_store, env, host_env::mm_filter_log_string),
        },
    }
}
