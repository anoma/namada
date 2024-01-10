//! The wasm host environment.
//!
//! Here, we expose the host functions into wasm's
//! imports, so they can be called from inside the wasm.

use namada_core::types::hash::StorageHasher;
use wasmer::{
    Function, HostEnvInitError, ImportObject, Instance, Memory, Store,
    WasmerEnv,
};

use crate::vm::host_env::{TxVmEnv, VpEvaluator, VpVmEnv};
use crate::vm::wasm::memory::WasmMemory;
use crate::vm::{host_env, WasmCacheAccess};

impl<DB, H, CA> WasmerEnv for TxVmEnv<'_, WasmMemory, DB, H, CA>
where
    DB: namada_state::DB + for<'iter> namada_state::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

impl<DB, H, EVAL, CA> WasmerEnv for VpVmEnv<'_, WasmMemory, DB, H, EVAL, CA>
where
    DB: namada_state::DB + for<'iter> namada_state::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// transaction code
#[allow(clippy::too_many_arguments)]
pub fn tx_imports<DB, H, CA>(
    wasm_store: &Store,
    initial_memory: Memory,
    env: TxVmEnv<'static, WasmMemory, DB, H, CA>,
) -> ImportObject
where
    DB: namada_state::DB + for<'iter> namada_state::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            // Wasm middleware gas injection hook
            "gas" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_charge_gas),
            // Whitelisted gas exposed function, we need two different functions just because of colliding names in the vm_host_env macro to generate implementations
            "namada_tx_charge_gas" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_charge_gas),
            "namada_tx_read" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_read),
            "namada_tx_result_buffer" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_result_buffer),
            "namada_tx_has_key" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_has_key),
            "namada_tx_write" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_write),
            "namada_tx_write_temp" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_write_temp),
            "namada_tx_delete" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_delete),
            "namada_tx_iter_prefix" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_iter_prefix),
            "namada_tx_iter_next" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_iter_next),
            "namada_tx_insert_verifier" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_insert_verifier),
            "namada_tx_update_validity_predicate" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_update_validity_predicate),
            "namada_tx_init_account" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_init_account),
            "namada_tx_emit_ibc_event" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_emit_ibc_event),
            "namada_tx_get_ibc_events" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_get_ibc_events),
            "namada_tx_get_chain_id" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_get_chain_id),
            "namada_tx_get_tx_index" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_get_tx_index),
            "namada_tx_get_block_height" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_get_block_height),
            "namada_tx_get_block_header" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_get_block_header),
            "namada_tx_get_block_hash" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_get_block_hash),
            "namada_tx_get_block_epoch" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_get_block_epoch),
            "namada_tx_get_pred_epochs" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_get_pred_epochs),
            "namada_tx_get_native_token" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_get_native_token),
            "namada_tx_log_string" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_log_string),
            "namada_tx_ibc_execute" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_ibc_execute),
            "namada_tx_set_commitment_sentinel" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_set_commitment_sentinel),
            "namada_tx_verify_tx_section_signature" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_verify_tx_section_signature),
            "namada_tx_update_masp_note_commitment_tree" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_update_masp_note_commitment_tree)
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// validity predicate code
pub fn vp_imports<DB, H, EVAL, CA>(
    wasm_store: &Store,
    initial_memory: Memory,
    env: VpVmEnv<'static, WasmMemory, DB, H, EVAL, CA>,
) -> ImportObject
where
    DB: namada_state::DB + for<'iter> namada_state::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator<Db = DB, H = H, Eval = EVAL, CA = CA>,
    CA: WasmCacheAccess,
{
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            // Wasm middleware gas injection hook
            "gas" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_charge_gas),
            // Whitelisted gas exposed function, we need two different functions just because of colliding names in the vm_host_env macro to generate implementations
            "namada_vp_charge_gas" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_charge_gas),
            "namada_vp_read_pre" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_read_pre),
            "namada_vp_read_post" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_read_post),
            "namada_vp_read_temp" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_read_temp),
            "namada_vp_result_buffer" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_result_buffer),
            "namada_vp_has_key_pre" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_has_key_pre),
            "namada_vp_has_key_post" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_has_key_post),
            "namada_vp_iter_prefix_pre" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_iter_prefix_pre),
            "namada_vp_iter_prefix_post" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_iter_prefix_pre),
            "namada_vp_iter_next" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_iter_next),
            "namada_vp_get_chain_id" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_get_chain_id),
            "namada_vp_get_tx_index" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_get_tx_index),
            "namada_vp_get_block_height" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_get_block_height),
            "namada_vp_get_block_header" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_get_block_header),
            "namada_vp_get_block_hash" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_get_block_hash),
            "namada_vp_get_tx_code_hash" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_get_tx_code_hash),
            "namada_vp_get_block_epoch" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_get_block_epoch),
            "namada_vp_get_ibc_events" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_get_ibc_events),
            "namada_vp_verify_tx_section_signature" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_verify_tx_section_signature),
            "namada_vp_eval" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_eval),
            "namada_vp_get_native_token" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_get_native_token),
            "namada_vp_log_string" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_log_string),
        },
    }
}
