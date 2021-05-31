use std::collections::HashSet;
use std::convert::TryInto;

use borsh::{BorshDeserialize, BorshSerialize};
use wasmer::{
    Function, HostEnvInitError, ImportObject, Instance, Memory, Store,
    WasmerEnv,
};

use super::wasm_memory::WasmMemory;
use crate::ledger::gas::{BlockGasMeter, VpGasMeter};
use crate::ledger::storage::write_log::{self, WriteLog};
use crate::ledger::storage::{self, Storage, StorageHasher};
use crate::types::internal::HostEnvResult;
use crate::types::key::ed25519::{
    verify_signature_raw, PublicKey, Signature, SignedTxData,
};
use crate::types::{Address, Key};
use crate::vm::host_env::{FilterEnv, MatchmakerEnv, TxEnv, VpEnv};
use crate::vm::memory::VmMemory;
use crate::vm::prefix_iter::{PrefixIteratorId, PrefixIterators};
use crate::vm::types::KeyVal;
use crate::vm::{
    host_env, EnvHostSliceWrapper, EnvHostWrapper, MutEnvHostWrapper,
};

const VERIFY_TX_SIG_GAS_COST: u64 = 1000;
const WASM_VALIDATION_GAS_PER_BYTE: u64 = 1;

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

impl<DB, H> WasmerEnv for VpEnv<'_, WasmMemory, DB, H>
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

impl WasmerEnv for MatchmakerEnv {
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

impl WasmerEnv for FilterEnv {
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
            "anoma_tx_read" => Function::new_native_with_env(wasm_store,
                                                                  env.clone(),
                                                                  host_env::tx_read),
            "anoma_tx_has_key" => Function::new_native_with_env(wasm_store,
                                                                     env.clone(),
                                                                     host_env::tx_has_key),
            "anoma_tx_write" => Function::new_native_with_env(wasm_store,
                                                                   env.clone(),
                                                                   host_env::tx_write),
            "anoma_tx_delete" => Function::new_native_with_env(wasm_store,
                                                                    env.clone(),
                                                                    host_env::tx_delete),
            "anoma_tx_iter_prefix" => Function::new_native_with_env(wasm_store,
                                                                         env.clone(),
                                                                         host_env::tx_iter_prefix),
            "anoma_tx_iter_next" => Function::new_native_with_env(wasm_store,
                                                                       env.clone(),
                                                                       host_env::tx_iter_next),
            "anoma_tx_insert_verifier" => Function::new_native_with_env(wasm_store,
                                                                             env.clone(),
                                                                             host_env::tx_insert_verifier),
            "anoma_tx_update_validity_predicate" => Function::new_native_with_env(wasm_store,
                                                                                       env.clone(),
                                                                                       host_env::tx_update_validity_predicate),
            "anoma_tx_init_account" => Function::new_native_with_env(wasm_store,
                                                                          env.clone(),
                                                                          host_env::tx_init_account),
            "anoma_tx_get_chain_id" => Function::new_native_with_env(wasm_store,
                                                                          env.clone(),
                                                                          host_env::tx_get_chain_id),
            "anoma_tx_get_block_height" => Function::new_native_with_env(wasm_store,
                                                                              env.clone(),
                                                                              host_env::tx_get_block_height),
            "anoma_tx_get_block_hash" => Function::new_native_with_env(wasm_store,
                                                                            env.clone(),
                                                                            host_env::tx_get_block_hash),
            "anoma_tx_log_string" => Function::new_native_with_env(wasm_store, env.clone(), host_env::tx_log_string),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// validity predicate code
#[allow(clippy::too_many_arguments)]
pub fn prepare_vp_env<DB, H>(
    wasm_store: &Store,
    addr: Address,
    storage: EnvHostWrapper<'static, &'static Storage<DB, H>>,
    write_log: EnvHostWrapper<'static, &WriteLog>,
    iterators: MutEnvHostWrapper<'static, &PrefixIterators<'static, DB>>,
    gas_meter: MutEnvHostWrapper<'static, &VpGasMeter>,
    tx_code: EnvHostSliceWrapper<'static, &[u8]>,
    initial_memory: Memory,
    keys_changed: EnvHostSliceWrapper<'static, &[Key]>,
    verifiers: EnvHostWrapper<'static, &'static HashSet<Address>>,
) -> ImportObject
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let env = VpEnv {
        memory: WasmMemory::default(),
        address: addr,
        storage,
        write_log,
        iterators,
        gas_meter,
        tx_code,
        verifiers,
        keys_changed,
    };
    prepare_vp_imports(wasm_store, initial_memory, &env)
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// validity predicate code
pub fn prepare_vp_imports<DB, H>(
    wasm_store: &Store,
    initial_memory: Memory,
    env: &VpEnv<'static, WasmMemory, DB, H>,
) -> ImportObject
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "gas" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_charge_gas),
            "anoma_vp_read_pre" => Function::new_native_with_env(wasm_store,
                                                                      env.clone(),
                                                                      host_env::vp_read_pre),
            "anoma_vp_read_post" => Function::new_native_with_env(wasm_store,
                                                                       env.clone(),
                                                                       host_env::vp_read_post),
            "anoma_vp_has_key_pre" => Function::new_native_with_env(wasm_store,
                                                                         env.clone(),
                                                                         host_env::vp_has_key_pre),
            "anoma_vp_has_key_post" => Function::new_native_with_env(wasm_store,
                                                                          env.clone(),
                                                                          host_env::vp_has_key_post),
            "anoma_vp_iter_prefix" => Function::new_native_with_env(wasm_store,
                                                                         env.clone(),
                                                                         host_env::vp_iter_prefix),
            "anoma_vp_iter_pre_next" => Function::new_native_with_env(wasm_store,
                                                                           env.clone(),
                                                                           host_env::vp_iter_pre_next),
            "anoma_vp_iter_post_next" => Function::new_native_with_env(wasm_store,
                                                                            env.clone(),
                                                                            host_env::vp_iter_post_next),
            "anoma_vp_get_chain_id" => Function::new_native_with_env(wasm_store,
                                                                          env.clone(),
                                                                          host_env::vp_get_chain_id),
            "anoma_vp_get_block_height" => Function::new_native_with_env(wasm_store,
                                                                              env.clone(),
                                                                              host_env::vp_get_block_height),
            "anoma_vp_get_block_hash" => Function::new_native_with_env(wasm_store,
                                                                            env.clone(),
                                                                            host_env::vp_get_block_hash),
            "anoma_vp_verify_tx_signature" => Function::new_native_with_env(wasm_store,
                                                                                 env.clone(),
                                                                                 host_env::vp_verify_tx_signature),
            "anoma_vp_eval" => Function::new_native_with_env(wasm_store,
                                                                                 env.clone(),
                                                                                 host_env::vp_eval),
            "anoma_vp_log_string" => Function::new_native_with_env(wasm_store, env.clone(), host_env::vp_log_string),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// matchmaker code
pub fn prepare_matchmaker_imports(
    wasm_store: &Store,
    initial_memory: Memory,
    /* tx_code: impl AsRef<[u8]>,
     * inject_mm_message: Sender<MatchmakerMessage>, */
) -> ImportObject {
    let env = MatchmakerEnv {
        memory: WasmMemory::default(),
        /* inject_mm_message,
         * tx_code: tx_code.as_ref().to_vec(), */
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "anoma_mm_send_match" => Function::new_native_with_env(wasm_store,
                                                                        env.clone(),
                                                                        send_match),
            "anoma_mm_update_data" => Function::new_native_with_env(wasm_store,
                                                                         env.clone(),
                                                                         update_data),
            "anoma_mm_remove_intents" => Function::new_native_with_env(wasm_store,
                                                                            env.clone(),
                                                                            remove_intents),
            "anoma_mm_log_string" => Function::new_native_with_env(wasm_store,
                                                                        env,
                                                                        matchmaker_log_string),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// filter code
pub fn prepare_filter_imports(
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
            "anoma_filter_log_string" => Function::new_native_with_env(wasm_store,
                                                                        env,
                                                                        filter_log_string),
        },
    }
}

/// Log a string from exposed to the wasm VM matchmaker environment. The message
/// will be printed at the [`tracing::Level::Info`]. This function is for ///
/// development only.
fn matchmaker_log_string(env: &MatchmakerEnv, str_ptr: u64, str_len: u64) {
    let (str, _gas) = env.memory.read_string(str_ptr, str_len as _);

    tracing::info!("WASM Matchmaker log: {}", str);
}

/// Log a string from exposed to the wasm VM filter environment. The message
/// will be printed at the [`tracing::Level::Info`].
fn filter_log_string(env: &FilterEnv, str_ptr: u64, str_len: u64) {
    let (str, _gas) = env.memory.read_string(str_ptr, str_len as _);
    tracing::info!("WASM Filter log: {}", str);
}

fn remove_intents(
    env: &MatchmakerEnv,
    intents_id_ptr: u64,
    intents_id_len: u64,
) {
    let (intents_id_bytes, _gas) =
        env.memory.read_bytes(intents_id_ptr, intents_id_len as _);

    let intents_id =
        HashSet::<Vec<u8>>::try_from_slice(&intents_id_bytes).unwrap();

    // env.inject_mm_message
    //     .try_send(MatchmakerMessage::RemoveIntents(intents_id))
    //     .expect("failed to send intents_id")
}

/// Inject a transaction from matchmaker's matched intents to the ledger
fn send_match(env: &MatchmakerEnv, data_ptr: u64, data_len: u64) {
    let (tx_data, _gas) = env.memory.read_bytes(data_ptr, data_len as _);
    // TODO sign in the matchmaker module instead. use a ref for the tx_code
    // here to avoid copying
    // let tx_code = env.tx_code.clone();
    // let keypair = wallet::matchmaker_keypair();
    // let signed = SignedTxData::new(&keypair, tx_data, &tx_code);
    // let signed_bytes = signed
    //     .try_to_vec()
    //     .expect("Couldn't encoded signed matchmaker tx data");
    // let tx = Tx {
    //     code: tx_code,
    //     data: Some(signed_bytes),
    //     timestamp: Some(std::time::SystemTime::now().into()),
    // };
    // env.inject_mm_message
    //     .try_send(MatchmakerMessage::InjectTx(tx))
    //     .expect("failed to send tx")
}

fn update_data(env: &MatchmakerEnv, data_ptr: u64, data_len: u64) {
    let (data, _gas) = env.memory.read_bytes(data_ptr, data_len as _);

    // env.inject_mm_message
    //     .try_send(MatchmakerMessage::UpdateData(data))
    //     .expect("failed to send updated data")
}
