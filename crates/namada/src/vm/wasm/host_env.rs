//! The wasm host environment.
//!
//! Here, we expose the host functions into wasm's
//! imports, so they can be called from inside the wasm.

use namada_state::{DBIter, StorageHasher, DB};
use wasmer::{Function, FunctionEnv, Imports, Instance, Store};

use crate::vm::host_env::{TxVmEnv, VpEvaluator, VpVmEnv};
use crate::vm::wasm::memory::WasmMemory;
use crate::vm::{host_env, WasmCacheAccess};

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// transaction code
#[allow(clippy::too_many_arguments)]
pub fn tx_imports<D, H, CA>(
    wasm_store: &mut Store,
    env: &FunctionEnv<TxVmEnv<'static, WasmMemory, DB, H, CA>>,
) -> Imports
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
    CA: WasmCacheAccess + 'static,
{
    wasmer::imports! {
        // default namespace
        "env" => {
            // Gas injection hook
            "gas" => Function::new_typed_with_env(wasm_store, env, host_env::tx_charge_gas),
            // Tx Host functions
            "namada_tx_delete" => Function::new_typed_with_env(wasm_store, env, host_env::tx_delete),
            "namada_tx_emit_event" => Function::new_typed_with_env(wasm_store, env, host_env::tx_emit_event),
            "namada_tx_get_block_epoch" => Function::new_typed_with_env(wasm_store, env, host_env::tx_get_block_epoch),
            "namada_tx_get_block_header" => Function::new_typed_with_env(wasm_store, env, host_env::tx_get_block_header),
            "namada_tx_get_block_height" => Function::new_typed_with_env(wasm_store, env, host_env::tx_get_block_height),
            "namada_tx_get_chain_id" => Function::new_typed_with_env(wasm_store, env, host_env::tx_get_chain_id),
            "namada_tx_get_events" => Function::new_typed_with_env(wasm_store, env, host_env::tx_get_events),
            "namada_tx_get_native_token" => Function::new_typed_with_env(wasm_store, env, host_env::tx_get_native_token),
            "namada_tx_get_pred_epochs" => Function::new_typed_with_env(wasm_store, env, host_env::tx_get_pred_epochs),
            "namada_tx_get_tx_index" => Function::new_typed_with_env(wasm_store, env, host_env::tx_get_tx_index),
            "namada_tx_has_key" => Function::new_typed_with_env(wasm_store, env, host_env::tx_has_key),
            "namada_tx_ibc_execute" => Function::new_typed_with_env(wasm_store, env, host_env::tx_ibc_execute),
            "namada_tx_init_account" => Function::new_typed_with_env(wasm_store, env, host_env::tx_init_account),
            "namada_tx_insert_verifier" => Function::new_typed_with_env(wasm_store, env, host_env::tx_insert_verifier),
            "namada_tx_iter_next" => Function::new_typed_with_env(wasm_store, env, host_env::tx_iter_next),
            "namada_tx_iter_prefix" => Function::new_typed_with_env(wasm_store, env, host_env::tx_iter_prefix),
            "namada_tx_log_string" => Function::new_typed_with_env(wasm_store, env, host_env::tx_log_string),
            "namada_tx_read" => Function::new_typed_with_env(wasm_store, env, host_env::tx_read),
            "namada_tx_read_temp" => Function::new_typed_with_env(wasm_store, env, host_env::tx_read_temp),
            "namada_tx_result_buffer" => Function::new_typed_with_env(wasm_store, env, host_env::tx_result_buffer),
            "namada_tx_set_commitment_sentinel" => Function::new_typed_with_env(wasm_store, env, host_env::tx_set_commitment_sentinel),
            "namada_tx_update_masp_note_commitment_tree" => Function::new_typed_with_env(wasm_store, env, host_env::tx_update_masp_note_commitment_tree),
            "namada_tx_update_validity_predicate" => Function::new_typed_with_env(wasm_store, env, host_env::tx_update_validity_predicate),
            "namada_tx_verify_tx_section_signature" => Function::new_typed_with_env(wasm_store, env, host_env::tx_verify_tx_section_signature),
            "namada_tx_write" => Function::new_typed_with_env(wasm_store, env, host_env::tx_write),
            "namada_tx_write_temp" => Function::new_typed_with_env(wasm_store, env, host_env::tx_write_temp),
            "namada_tx_yield_value" => Function::new_typed_with_env(wasm_store, env, host_env::tx_yield_value),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// validity predicate code
pub fn vp_imports<D, H, EVAL, CA>(
    wasm_store: &Store,
    env: VpVmEnv<WasmMemory, D, H, EVAL, CA>,
) -> ImportObject
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
    EVAL: VpEvaluator<Db = D, H = H, Eval = EVAL, CA = CA> + 'static,
    CA: WasmCacheAccess + 'static,
{
    wasmer::imports! {
        // default namespace
        "env" => {
            // Wasm middleware gas injection hook
            "gas" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_charge_gas),
            // VP Host functions
            "namada_vp_eval" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_eval),
            "namada_vp_get_block_header" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_get_block_header),
            "namada_vp_get_block_height" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_get_block_height),
            "namada_vp_get_chain_id" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_get_chain_id),
            "namada_vp_get_events" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_get_events),
            "namada_vp_get_native_token" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_get_native_token),
            "namada_vp_get_pred_epochs" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_get_pred_epochs),
            "namada_vp_get_tx_code_hash" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_get_tx_code_hash),
            "namada_vp_get_tx_index" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_get_tx_index),
            "namada_vp_has_key_post" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_has_key_post),
            "namada_vp_has_key_pre" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_has_key_pre),
            "namada_vp_iter_next" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_iter_next),
            "namada_vp_iter_prefix_post" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_iter_prefix_pre),
            "namada_vp_iter_prefix_pre" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_iter_prefix_pre),
            "namada_vp_log_string" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_log_string),
            "namada_vp_read_post" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_read_post),
            "namada_vp_read_pre" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_read_pre),
            "namada_vp_read_temp" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_read_temp),
            "namada_vp_result_buffer" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_result_buffer),
            "namada_vp_verify_masp" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_verify_masp),
            "namada_vp_verify_tx_section_signature" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_verify_tx_section_signature),
            "namada_vp_yield_value" => Function::new_typed_with_env(wasm_store, &env, host_env::vp_yield_value),
        },
    }
}
