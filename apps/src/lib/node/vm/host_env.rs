use std::collections::HashSet;
use std::convert::TryInto;

use anoma_shared::protocol::gas::{BlockGasMeter, VpGasMeter};
use anoma_shared::protocol::storage::{self, Storage, StorageHasher};
use anoma_shared::protocol::vm::host_env;
use anoma_shared::protocol::vm::host_env::{TxEnv, VpEnv};
use anoma_shared::protocol::vm::memory::VmMemory;
use anoma_shared::protocol::vm::prefix_iter::{
    PrefixIteratorId, PrefixIterators,
};
use anoma_shared::protocol::vm::write_log::{self, WriteLog};
use anoma_shared::types::internal::HostEnvResult;
use anoma_shared::types::key::ed25519::{
    verify_signature_raw, PublicKey, Signature, SignedTxData,
};
use anoma_shared::types::{Address, Key};
use anoma_shared::vm_memory::KeyVal;
use borsh::{BorshDeserialize, BorshSerialize};
use tokio::sync::mpsc::Sender;
use wasmer::Function::new_native_with_env;
use wasmer::{
    HostEnvInitError, ImportObject, Instance, Memory, Store, WasmerEnv,
};

use super::memory::WasmMemory;
use super::{EnvHostWrapper, MutEnvHostWrapper};
use crate::proto::types::Tx;
use crate::types::MatchmakerMessage;
use crate::wallet;

const VERIFY_TX_SIG_GAS_COST: u64 = 1000;
const WASM_VALIDATION_GAS_PER_BYTE: u64 = 1;

#[derive[Clone]]
pub struct TxWasmEnv {
    host: TxHost<storage::PersistentDB, storage::PersistentStorageHasher>,
    memory: WasmMemory,
}

impl WasmerEnv for TxWasmEnv {
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

impl TxEnv for TxWasmEnv {
    fn memory(&self) -> &MEM {
        self.memory
    }

    fn storage(&self) -> &PersistentStorage {
        let storage = self.host.storage;
        unsafe { &*(storage.get()) }
    }

    fn write_log(&self) -> &mut WriteLog {
        let write_log = self.host.write_log;
        unsafe { &mut *(write_log.get()) }
    }

    fn iterators(&self) -> &mut PrefixIterators<'static, DB> {
        let iterators = self.host.iterators;
        unsafe { &mut *(iterators.get()) }
    }

    fn gas_meter(&self) -> &mut BlockGasMeter {
        let gas_meter = self.host.gas_meter;
        unsafe { &mut *(gas_meter.get()) }
    }

    fn verifiers(&self) -> &mut HashSet<Address> {
        let verifiers = self.host.verifiers;
        unsafe { &mut *(verifiers.get()) }
    }
}
#[derive[Clone]]
pub struct VpWasmEnv {
    host: VpHost<storage::PersistentDB, storage::PersistentStorageHasher>,
    memory: WasmMemory,
}

impl WasmerEnv for VpWasmEnv {
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

impl VpEnv for VpWasmEnv {
    fn memory(&self) -> &MEM {
        self.memory
    }

    fn address(&self) -> &Address {
        self.host.address
    }

    fn storage(&self) -> &Storage<DB, H> {
        let storage = self.host.storage;
        unsafe { &*(storage.get()) }
    }

    fn write_log(&self) -> &WriteLog {
        let write_log = self.host.write_log;
        unsafe { &*(write_log.get()) }
    }

    fn iterators(&self) -> &mut PrefixIterators<'static, DB> {
        let iterators = self.host.iterators;
        unsafe { &mut *(iterators.get()) }
    }

    fn verifiers(&self) -> &mut HashSet<Address> {
        let verifiers = self.host.verifiers;
        unsafe { &mut *(verifiers.get()) }
    }

    fn gas_meter(&self) -> &mut VpGasMeter {
        let gas_meter = self.host.gas_meter;
        unsafe { &mut *(gas_meter.get()) }
    }

    fn tx_code(&self) -> &Vec<u8> {
        let tx_code = self.host.tx_code;
        unsafe { &*(tx_code.get()) }
    }
}

#[derive(Clone)]
pub struct MatchmakerEnv {
    pub tx_code: Vec<u8>,
    pub inject_mm_message: Sender<MatchmakerMessage>,
    pub memory: WasmMemory,
}

impl WasmerEnv for MatchmakerEnv {
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

#[derive(Clone)]
pub struct FilterEnv {
    pub memory: WasmMemory,
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
pub fn prepare_tx_imports(
    wasm_store: &Store,
    storage: EnvHostWrapper<PersistentStorage>,
    write_log: MutEnvHostWrapper<WriteLog>,
    iterators: MutEnvHostWrapper<
        PrefixIterators<'static, storage::PersistentDB>,
    >,
    verifiers: MutEnvHostWrapper<HashSet<Address>>,
    gas_meter: MutEnvHostWrapper<BlockGasMeter>,
    initial_memory: Memory,
) -> ImportObject {
    let env = TxWasmEnv {
        host: TxHost {
            storage,
            write_log,
            iterators,
            verifiers,
            gas_meter,
        },
        memory: WasmMemory::default(),
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "gas" => new_native_with_env(wasm_store, env.clone(), host_env::tx_charge_gas),
            "anoma_tx_read" => new_native_with_env(wasm_store,
                                                                  env.clone(),
                                                                  host_env::tx_read),
            "anoma_tx_has_key" => new_native_with_env(wasm_store,
                                                                     env.clone(),
                                                                     host_env::tx_has_key),
            "anoma_tx_write" => new_native_with_env(wasm_store,
                                                                   env.clone(),
                                                                   host_env::tx_write),
            "anoma_tx_delete" => new_native_with_env(wasm_store,
                                                                    env.clone(),
                                                                    host_env::tx_delete),
            "anoma_tx_iter_prefix" => new_native_with_env(wasm_store,
                                                                         env.clone(),
                                                                         host_env::tx_iter_prefix),
            "anoma_tx_iter_next" => new_native_with_env(wasm_store,
                                                                       env.clone(),
                                                                       host_env::tx_iter_next),
            "anoma_tx_insert_verifier" => new_native_with_env(wasm_store,
                                                                             env.clone(),
                                                                             host_env::tx_insert_verifier),
            "anoma_tx_update_validity_predicate" => new_native_with_env(wasm_store,
                                                                                       env.clone(),
                                                                                       host_env::tx_update_validity_predicate),
            "anoma_tx_init_account" => new_native_with_env(wasm_store,
                                                                          env.clone(),
                                                                          host_env::tx_init_account),
            "anoma_tx_get_chain_id" => new_native_with_env(wasm_store,
                                                                          env.clone(),
                                                                          host_env::tx_get_chain_id),
            "anoma_tx_get_block_height" => new_native_with_env(wasm_store,
                                                                              env.clone(),
                                                                              host_env::tx_get_block_height),
            "anoma_tx_get_block_hash" => new_native_with_env(wasm_store,
                                                                            env.clone(),
                                                                            host_env::tx_get_block_hash),
            "anoma_tx_log_string" => new_native_with_env(wasm_store, env, host_env::tx_log_string),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// validity predicate code
#[allow(clippy::too_many_arguments)]
pub fn prepare_vp_imports(
    wasm_store: &Store,
    addr: Address,
    storage: EnvHostWrapper<PersistentStorage>,
    write_log: EnvHostWrapper<WriteLog>,
    iterators: MutEnvHostWrapper<
        PrefixIterators<'static, storage::PersistentDB>,
    >,
    gas_meter: MutEnvHostWrapper<VpGasMeter>,
    tx_code: EnvHostWrapper<Vec<u8>>,
    initial_memory: Memory,
) -> ImportObject {
    let env = VpWasmEnv {
        host: VpHost {
            addr,
            storage,
            write_log,
            iterators,
            gas_meter,
            tx_code,
        },
        memory: WasmMemory::default(),
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "gas" => new_native_with_env(wasm_store, env.clone(), host_env::vp_charge_gas),
            "anoma_vp_read_pre" => new_native_with_env(wasm_store,
                                                                      env.clone(),
                                                                      host_env::vp_read_pre),
            "anoma_vp_read_post" => new_native_with_env(wasm_store,
                                                                       env.clone(),
                                                                       host_env::vp_read_post),
            "anoma_vp_has_key_pre" => new_native_with_env(wasm_store,
                                                                         env.clone(),
                                                                         host_env::vp_has_key_pre),
            "anoma_vp_has_key_post" => new_native_with_env(wasm_store,
                                                                          env.clone(),
                                                                          host_env::vp_has_key_post),
            "anoma_vp_iter_prefix" => new_native_with_env(wasm_store,
                                                                         env.clone(),
                                                                         host_env::vp_iter_prefix),
            "anoma_vp_iter_pre_next" => new_native_with_env(wasm_store,
                                                                           env.clone(),
                                                                           host_env::vp_iter_pre_next),
            "anoma_vp_iter_post_next" => new_native_with_env(wasm_store,
                                                                            env.clone(),
                                                                            host_env::vp_iter_post_next),
            "anoma_vp_get_chain_id" => new_native_with_env(wasm_store,
                                                                          env.clone(),
                                                                          host_env::vp_get_chain_id),
            "anoma_vp_get_block_height" => new_native_with_env(wasm_store,
                                                                              env.clone(),
                                                                              host_env::vp_get_block_height),
            "anoma_vp_get_block_hash" => new_native_with_env(wasm_store,
                                                                            env.clone(),
                                                                            host_env::vp_get_block_hash),
            "anoma_vp_verify_tx_signature" => new_native_with_env(wasm_store,
                                                                                 env.clone(),
                                                                                 host_env::vp_verify_tx_signature),
            "anoma_vp_log_string" => new_native_with_env(wasm_store, env, host_env::vp_log_string),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// matchmaker code
pub fn prepare_matchmaker_imports(
    wasm_store: &Store,
    initial_memory: Memory,
    tx_code: impl AsRef<[u8]>,
    inject_mm_message: Sender<MatchmakerMessage>,
) -> ImportObject {
    let env = MatchmakerEnv {
        memory: WasmMemory::default(),
        inject_mm_message,
        tx_code: tx_code.as_ref().to_vec(),
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "anoma_mm_send_match" => new_native_with_env(wasm_store,
                                                                        env.clone(),
                                                                        send_match),
            "anoma_mm_update_data" => new_native_with_env(wasm_store,
                                                                         env.clone(),
                                                                         update_data),
            "anoma_mm_remove_intents" => new_native_with_env(wasm_store,
                                                                            env.clone(),
                                                                            remove_intents),
            "anoma_mm_log_string" => new_native_with_env(wasm_store,
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
            "anoma_filter_log_string" => new_native_with_env(wasm_store,
                                                                        env,
                                                                        filter_log_string),
        },
    }
}
