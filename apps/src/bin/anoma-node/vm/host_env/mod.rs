pub mod prefix_iter;
pub mod write_log;

use std::collections::HashSet;
use std::convert::TryInto;

use anoma::protobuf::types::Tx;
use anoma_shared::types::key::ed25519::{
    verify_signature_raw, PublicKey, Signature,
};
use anoma_shared::types::{Address, Key, KeySeg, RawAddress};
use anoma_shared::vm_memory::KeyVal;
use borsh::{BorshDeserialize, BorshSerialize};
use tokio::sync::mpsc::Sender;
use wasmer::{
    HostEnvInitError, ImportObject, Instance, Memory, Store, WasmerEnv,
};

use self::prefix_iter::{PrefixIteratorId, PrefixIterators};
use self::write_log::WriteLog;
use super::memory::AnomaMemory;
use super::{EnvHostWrapper, MutEnvHostWrapper};
use crate::shell::gas::{BlockGasMeter, VpGasMeter};
use crate::shell::storage::Storage;

#[derive(Clone)]
struct TxEnv<'a> {
    storage: EnvHostWrapper<Storage>,
    // not thread-safe, assuming single-threaded Tx runner
    write_log: MutEnvHostWrapper<WriteLog>,
    // not thread-safe, assuming single-threaded Tx runner
    iterators: MutEnvHostWrapper<PrefixIterators<'a>>,
    // not thread-safe, assuming single-threaded Tx runner
    verifiers: MutEnvHostWrapper<HashSet<Address>>,
    // not thread-safe, assuming single-threaded Tx runner
    gas_meter: MutEnvHostWrapper<BlockGasMeter>,
    memory: AnomaMemory,
}

impl<'a> WasmerEnv for TxEnv<'a> {
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

#[derive(Clone)]
struct VpEnv<'a> {
    /// The address of the account that owns the VP
    addr: Address,
    // this is not thread-safe, but because each VP has its own instance there
    // is no shared access
    iterators: MutEnvHostWrapper<PrefixIterators<'a>>,
    // thread-safe read-only access from parallel Vp runners
    storage: EnvHostWrapper<Storage>,
    // thread-safe read-only access from parallel Vp runners
    write_log: EnvHostWrapper<WriteLog>,
    // TODO In parallel runs, we can change only the maximum used gas of all
    // the VPs that we ran.
    gas_meter: MutEnvHostWrapper<VpGasMeter>,
    // The transaction code is used for signature verification
    tx_code: Vec<u8>,
    memory: AnomaMemory,
}

impl<'a> WasmerEnv for VpEnv<'a> {
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

#[derive(Clone)]
pub struct MatchmakerEnv {
    pub tx_code: Vec<u8>,
    pub inject_tx: Sender<Tx>,
    pub memory: AnomaMemory,
}

impl WasmerEnv for MatchmakerEnv {
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
    storage: EnvHostWrapper<Storage>,
    write_log: MutEnvHostWrapper<WriteLog>,
    iterators: MutEnvHostWrapper<PrefixIterators<'static>>,
    verifiers: MutEnvHostWrapper<HashSet<Address>>,
    gas_meter: MutEnvHostWrapper<BlockGasMeter>,
    initial_memory: Memory,
) -> ImportObject {
    let env = TxEnv {
        storage,
        write_log,
        iterators,
        verifiers,
        gas_meter,
        memory: AnomaMemory::default(),
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "gas" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_charge_gas),
            "_read" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_read),
            "_has_key" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_has_key),
            "_write" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_write),
            "_delete" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_delete),
            "_read_varlen" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_read_varlen),
            "_iter_prefix" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_iter_prefix),
            "_iter_next" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_iter_next),
            "_iter_next_varlen" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_iter_next_varlen),
            "_insert_verifier" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_insert_verifier),
            "_update_validity_predicate" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_update_validity_predicate),
            "_init_account" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_init_account),
            "_get_chain_id" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_get_chain_id),
            "_get_block_height" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_get_block_height),
            "_get_block_hash" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_get_block_hash),
            "_log_string" => wasmer::Function::new_native_with_env(wasm_store, env, tx_log_string),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// validity predicate code
pub fn prepare_vp_imports(
    wasm_store: &Store,
    addr: Address,
    storage: EnvHostWrapper<Storage>,
    write_log: EnvHostWrapper<WriteLog>,
    iterators: MutEnvHostWrapper<PrefixIterators<'static>>,
    gas_meter: MutEnvHostWrapper<VpGasMeter>,
    tx_code: Vec<u8>,
    initial_memory: Memory,
) -> ImportObject {
    let env = VpEnv {
        addr,
        storage,
        write_log,
        iterators,
        gas_meter,
        tx_code,
        memory: AnomaMemory::default(),
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "gas" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_charge_gas),
            "_read_pre" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_read_pre),
            "_read_post" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_read_post),
            "_read_pre_varlen" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_read_pre_varlen),
            "_read_post_varlen" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_read_post_varlen),
            "_has_key_pre" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_has_key_pre),
            "_has_key_post" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_has_key_post),
            "_iter_prefix" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_iter_prefix),
            "_iter_pre_next" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_iter_pre_next),
            "_iter_post_next" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_iter_post_next),
            "_iter_pre_next_varlen" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_iter_pre_next_varlen),
            "_iter_post_next_varlen" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_iter_post_next_varlen),
            "_get_chain_id" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_get_chain_id),
            "_get_block_height" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_get_block_height),
            "_get_block_hash" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_get_block_hash),
            "_verify_tx_signature" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_verify_tx_signature),
            "_log_string" => wasmer::Function::new_native_with_env(wasm_store, env, vp_log_string),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// transaction code
pub fn prepare_matchmaker_imports(
    wasm_store: &Store,
    initial_memory: Memory,
    tx_code: impl AsRef<[u8]>,
    inject_tx: Sender<Tx>,
) -> ImportObject {
    let env = MatchmakerEnv {
        memory: AnomaMemory::default(),
        inject_tx,
        tx_code: tx_code.as_ref().to_vec(),
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "_send_match" => wasmer::Function::new_native_with_env(wasm_store,
                                                                  env.clone(),
                                                                  send_match),
            "_log_string" => wasmer::Function::new_native_with_env(wasm_store,
                                                                  env,
                                                                  matchmaker_log_string),
        },
    }
}

/// Called from tx wasm to request to use the given gas amount
fn tx_charge_gas(env: &TxEnv, used_gas: i32) {
    tx_add_gas(env, used_gas as _)
}

fn tx_add_gas(env: &TxEnv, used_gas: u64) {
    let gas_meter: &mut BlockGasMeter = unsafe { &mut *(env.gas_meter.get()) };
    // if we run out of gas, we need to stop the execution
    if let Err(err) = gas_meter.add(used_gas) {
        log::warn!(
            "Stopping transaction execution because of gas error: {}",
            err
        );
        unreachable!()
    }
}

/// Called from VP wasm to request to use the given gas amount
fn vp_charge_gas(env: &VpEnv, used_gas: i32) {
    vp_add_gas(env, used_gas as _)
}

fn vp_add_gas(env: &VpEnv, used_gas: u64) {
    let gas_meter: &mut VpGasMeter = unsafe { &mut *(env.gas_meter.get()) };
    if let Err(err) = gas_meter.add(used_gas) {
        log::warn!(
            "Stopping transaction execution because of gas error: {}",
            err
        );
        unreachable!()
    }
}

/// Storage read function exposed to the wasm VM Tx environment. It will try to
/// read from the write log first and if no entry found then from the storage.
fn tx_storage_read(
    env: &TxEnv,
    key_ptr: u64,
    key_len: u64,
    result_ptr: u64,
) -> u64 {
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    tx_add_gas(env, gas);

    log::debug!(
        "tx_storage_read {}, key {}, result_ptr {}",
        key,
        key_ptr,
        result_ptr,
    );

    let key = Key::parse(key).expect("Cannot parse the key string");

    // try to read from the write log first
    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    let (log_val, gas) = write_log.read(&key);
    tx_add_gas(env, gas);
    match log_val {
        Some(&write_log::StorageModification::Write { ref value }) => {
            let gas = env
                .memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
            tx_add_gas(env, gas);
            1
        }
        Some(&write_log::StorageModification::Delete) => {
            // fail, given key has been deleted
            0
        }
        Some(&write_log::StorageModification::InitAccount {
            ref vp, ..
        }) => {
            // read the VP of a new account
            let gas = env
                .memory
                .write_bytes(result_ptr, vp)
                .expect("cannot write to memory");
            tx_add_gas(env, gas);
            1
        }
        None => {
            // when not found in write log, try to read from the storage
            let storage: &Storage = unsafe { &*(env.storage.get()) };
            let (value, gas) = storage.read(&key).expect("storage read failed");
            tx_add_gas(env, gas);
            match value {
                Some(value) => {
                    let gas = env
                        .memory
                        .write_bytes(result_ptr, value)
                        .expect("cannot write to memory");
                    tx_add_gas(env, gas);
                    1
                }
                None => {
                    // fail, key not found
                    0
                }
            }
        }
    }
}

/// Storage `has_key` function exposed to the wasm VM Tx environment. It will
/// try to check the write log first and if no entry found then the storage.
fn tx_storage_has_key(env: &TxEnv, key_ptr: u64, key_len: u64) -> u64 {
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    tx_add_gas(env, gas);

    log::debug!("tx_storage_has_key {}, key {}", key, key_ptr,);

    let key = Key::parse(key).expect("Cannot parse the key string");

    // try to read from the write log first
    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    let (log_val, gas) = write_log.read(&key);
    tx_add_gas(env, gas);
    match log_val {
        Some(&write_log::StorageModification::Write { .. }) => 1,
        Some(&write_log::StorageModification::Delete) => {
            // the given key has been deleted
            0
        }
        Some(&write_log::StorageModification::InitAccount { .. }) => 1,
        None => {
            // when not found in write log, try to check the storage
            let storage: &Storage = unsafe { &*(env.storage.get()) };
            let (present, gas) =
                storage.has_key(&key).expect("storage has_key failed");
            tx_add_gas(env, gas);
            if present { 1 } else { 0 }
        }
    }
}

/// Storage read function exposed to the wasm VM Tx environment. It will try to
/// read from the write log first and if no entry found then from the storage.
///
/// Returns [`-1`] when the key is not present, or the length of the data when
/// the key is present (the length may be [`0`]).
fn tx_storage_read_varlen(
    env: &TxEnv,
    key_ptr: u64,
    key_len: u64,
    result_ptr: u64,
) -> i64 {
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    tx_add_gas(env, gas);

    log::debug!(
        "tx_storage_read {}, key {}, result_ptr {}",
        key,
        key_ptr,
        result_ptr,
    );

    let key = Key::parse(key).expect("Cannot parse the key string");

    // try to read from the write log first
    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    let (log_val, gas) = write_log.read(&key);
    tx_add_gas(env, gas);
    match log_val {
        Some(&write_log::StorageModification::Write { ref value }) => {
            let len: i64 =
                value.len().try_into().expect("data length overflow");
            let gas = env
                .memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
            tx_add_gas(env, gas);
            len
        }
        Some(&write_log::StorageModification::Delete) => {
            // fail, given key has been deleted
            -1
        }
        Some(&write_log::StorageModification::InitAccount {
            ref vp, ..
        }) => {
            // read the VP of a new account
            let len: i64 = vp.len() as _;
            let gas = env
                .memory
                .write_bytes(result_ptr, vp)
                .expect("cannot write to memory");
            tx_add_gas(env, gas);
            len
        }
        None => {
            // when not found in write log, try to read from the storage
            let storage: &Storage = unsafe { &*(env.storage.get()) };
            let (value, gas) = storage.read(&key).expect("storage read failed");
            tx_add_gas(env, gas);
            match value {
                Some(value) => {
                    let len: i64 =
                        value.len().try_into().expect("data length overflow");
                    let gas = env
                        .memory
                        .write_bytes(result_ptr, value)
                        .expect("cannot write to memory");
                    tx_add_gas(env, gas);
                    len
                }
                None => {
                    // fail, key not found
                    -1
                }
            }
        }
    }
}

/// Storage prefix iterator function exposed to the wasm VM Tx environment.
/// It will try to get an iterator from the storage and return the corresponding
/// ID of the interator.
fn tx_storage_iter_prefix(
    env: &TxEnv,
    prefix_ptr: u64,
    prefix_len: u64,
) -> u64 {
    let (prefix, gas) = env
        .memory
        .read_string(prefix_ptr, prefix_len as _)
        .expect("Cannot read the prefix from memory");
    tx_add_gas(env, gas);

    log::debug!("tx_storage_iter_prefix {}, prefix {}", prefix, prefix_ptr);

    let prefix = Key::parse(prefix).expect("Cannot parse the prefix string");

    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let iterators: &mut PrefixIterators =
        unsafe { &mut *(env.iterators.get()) };
    let (iter, gas) = storage.iter_prefix(&prefix);
    tx_add_gas(env, gas);
    iterators.insert(iter).id()
}

/// Storage prefix iterator next function exposed to the wasm VM Tx environment.
/// It will read a key value pair from the write log first and if no entry found
/// then from the storage.
fn tx_storage_iter_next(env: &TxEnv, iter_id: u64, result_ptr: u64) -> u64 {
    log::debug!(
        "tx_storage_iter_next iter_id {}, result_ptr {}",
        iter_id,
        result_ptr,
    );

    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    let iterators: &mut PrefixIterators =
        unsafe { &mut *(env.iterators.get()) };
    let iter_id = PrefixIteratorId::new(iter_id);
    while let Some((key, val, iter_gas)) = iterators.next(iter_id) {
        let (log_val, log_gas) = write_log.read(
            &Key::parse(key.clone()).expect("Cannot parse the key string"),
        );
        tx_add_gas(env, iter_gas + log_gas);
        match log_val {
            Some(&write_log::StorageModification::Write { ref value }) => {
                let key_val = KeyVal {
                    key,
                    val: value.clone(),
                }
                .try_to_vec()
                .expect("cannot serialize the key value pair");
                let gas = env
                    .memory
                    .write_bytes(result_ptr, key_val)
                    .expect("cannot write to memory");
                tx_add_gas(env, gas);
                return 1;
            }
            Some(&write_log::StorageModification::Delete) => {
                // check the next because the key has already deleted
                continue;
            }
            Some(&write_log::StorageModification::InitAccount { .. }) => {
                // a VP of a new account doesn't need to be iterated
                continue;
            }
            None => {
                let key_val = KeyVal { key, val }
                    .try_to_vec()
                    .expect("cannot serialize the key value pair");
                let gas = env
                    .memory
                    .write_bytes(result_ptr, key_val)
                    .expect("cannot write to memory");
                tx_add_gas(env, gas);
                return 1;
            }
        }
    }
    // fail, key not found
    0
}

/// Storage prefix iterator next function exposed to the wasm VM Tx environment.
/// It will try to read from the write log first and if no entry found then from
/// the storage.
///
/// Returns [`-1`] when the key is not present, or the length of the data when
/// the key is present (the length may be [`0`]).
fn tx_storage_iter_next_varlen(
    env: &TxEnv,
    iter_id: u64,
    result_ptr: u64,
) -> i64 {
    log::debug!(
        "tx_storage_iter_next iter_id {}, result_ptr {}",
        iter_id,
        result_ptr,
    );

    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    let iterators: &mut PrefixIterators =
        unsafe { &mut *(env.iterators.get()) };
    let iter_id = PrefixIteratorId::new(iter_id);
    while let Some((key, val, iter_gas)) = iterators.next(iter_id) {
        let (log_val, log_gas) = write_log.read(
            &Key::parse(key.clone()).expect("Cannot parse the key string"),
        );
        tx_add_gas(env, iter_gas + log_gas);
        match log_val {
            Some(&write_log::StorageModification::Write { ref value }) => {
                let key_val = KeyVal {
                    key,
                    val: value.clone(),
                }
                .try_to_vec()
                .expect("cannot serialize the key value pair");
                let len: i64 =
                    key_val.len().try_into().expect("data length overflow");
                let gas = env
                    .memory
                    .write_bytes(result_ptr, key_val)
                    .expect("cannot write to memory");
                tx_add_gas(env, gas);
                return len;
            }
            Some(&write_log::StorageModification::Delete) => {
                // check the next because the key has already deleted
                continue;
            }
            Some(&write_log::StorageModification::InitAccount { .. }) => {
                // a VP of a new account doesn't need to be iterated
                continue;
            }
            None => {
                let key_val = KeyVal { key, val }
                    .try_to_vec()
                    .expect("cannot serialize the key value pair");
                let len: i64 =
                    key_val.len().try_into().expect("data length overflow");
                let gas = env
                    .memory
                    .write_bytes(result_ptr, key_val)
                    .expect("cannot write to memory");
                tx_add_gas(env, gas);
                return len;
            }
        }
    }
    // key not found
    -1
}

/// Storage write function exposed to the wasm VM Tx environment. The given
/// key/value will be written to the write log.
fn tx_storage_write(
    env: &TxEnv,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
) {
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    tx_add_gas(env, gas);
    let (value, gas) = env
        .memory
        .read_bytes(val_ptr, val_len as _)
        .expect("Cannot read the value from memory");
    tx_add_gas(env, gas);

    log::debug!("tx_storage_update {}, {:#?}", key, value);

    let key = Key::parse(key).expect("Cannot parse the key string");

    let write_log: &mut WriteLog = unsafe { &mut *(env.write_log.get()) };
    let (gas, _size_diff) = write_log.write(&key, value);
    tx_add_gas(env, gas);
    // TODO: charge the size diff
}

/// Storage delete function exposed to the wasm VM Tx environment. The given
/// key/value will be written as deleted to the write log.
fn tx_storage_delete(env: &TxEnv, key_ptr: u64, key_len: u64) -> u64 {
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    tx_add_gas(env, gas);

    log::debug!("tx_storage_delete {}", key);

    let key = Key::parse(key).expect("Cannot parse the key string");

    let write_log: &mut WriteLog = unsafe { &mut *(env.write_log.get()) };
    let (gas, _size_diff) = write_log.delete(&key);
    tx_add_gas(env, gas);
    // TODO: charge the size diff

    1
}

/// Storage read prior state (before tx execution) function exposed to the wasm
/// VM VP environment. It will try to read from the storage.
fn vp_storage_read_pre(
    env: &VpEnv,
    key_ptr: u64,
    key_len: u64,
    result_ptr: u64,
) -> u64 {
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    vp_add_gas(env, gas);

    // try to read from the storage
    let key = Key::parse(key).expect("Cannot parse the key string");
    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let (value, gas) = storage.read(&key).expect("storage read failed");
    vp_add_gas(env, gas);
    log::debug!(
        "vp_storage_read_pre addr {}, key {}, value {:#?}",
        env.addr,
        key,
        value,
    );
    match value {
        Some(value) => {
            log::debug!("key {:#?} found", key);
            let gas = env
                .memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
            vp_add_gas(env, gas);
            1
        }
        None => {
            // fail, key not found
            0
        }
    }
}

/// Storage read posterior state (after tx execution) function exposed to the
/// wasm VM VP environment. It will try to read from the write log first and if
/// no entry found then from the storage.
fn vp_storage_read_post(
    env: &VpEnv,
    key_ptr: u64,
    key_len: u64,
    result_ptr: u64,
) -> u64 {
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    vp_add_gas(env, gas);

    log::debug!(
        "vp_storage_read_post {}, key {}, result_ptr {}",
        key,
        key_ptr,
        result_ptr,
    );

    // try to read from the write log first
    let key = Key::parse(key).expect("Cannot parse the key string");
    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    let (log_val, gas) = write_log.read(&key);
    vp_add_gas(env, gas);
    match log_val {
        Some(&write_log::StorageModification::Write { ref value }) => {
            let gas = env
                .memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
            vp_add_gas(env, gas);
            1
        }
        Some(&write_log::StorageModification::Delete) => {
            // fail, given key has been deleted
            0
        }
        Some(&write_log::StorageModification::InitAccount {
            ref vp, ..
        }) => {
            // read the VP of a new account
            let gas = env
                .memory
                .write_bytes(result_ptr, vp)
                .expect("cannot write to memory");
            vp_add_gas(env, gas);
            1
        }
        None => {
            // when not found in write log, try to read from the storage
            let storage: &Storage = unsafe { &*(env.storage.get()) };
            let (value, gas) = storage.read(&key).expect("storage read failed");
            vp_add_gas(env, gas);
            match value {
                Some(value) => {
                    let gas = env
                        .memory
                        .write_bytes(result_ptr, value)
                        .expect("cannot write to memory");
                    vp_add_gas(env, gas);
                    1
                }
                None => {
                    // fail, key not found
                    0
                }
            }
        }
    }
}

/// Storage read prior state (before tx execution) function exposed to the wasm
/// VM VP environment. It will try to read from the storage.
///
/// Returns [`-1`] when the key is not present, or the length of the data when
/// the key is present (the length may be [`0`]).
fn vp_storage_read_pre_varlen(
    env: &VpEnv,
    key_ptr: u64,
    key_len: u64,
    result_ptr: u64,
) -> i64 {
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    vp_add_gas(env, gas);

    // try to read from the storage
    let key = Key::parse(key).expect("Cannot parse the key string");
    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let (value, gas) = storage.read(&key).expect("storage read failed");
    vp_add_gas(env, gas);
    log::debug!(
        "vp_storage_read_pre addr {}, key {}, value {:#?}",
        env.addr,
        key,
        value,
    );
    match value {
        Some(value) => {
            let len: i64 =
                value.len().try_into().expect("data length overflow");
            let gas = env
                .memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
            vp_add_gas(env, gas);
            len
        }
        None => {
            // fail, key not found
            -1
        }
    }
}

/// Storage read posterior state (after tx execution) function exposed to the
/// wasm VM VP environment. It will try to read from the write log first and if
/// no entry found then from the storage.
///
/// Returns [`-1`] when the key is not present, or the length of the data when
/// the key is present (the length may be [`0`]).
fn vp_storage_read_post_varlen(
    env: &VpEnv,
    key_ptr: u64,
    key_len: u64,
    result_ptr: u64,
) -> i64 {
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    vp_add_gas(env, gas);

    log::debug!(
        "vp_storage_read_post {}, key {}, result_ptr {}",
        key,
        key_ptr,
        result_ptr,
    );

    // try to read from the write log first
    let key = Key::parse(key).expect("Cannot parse the key string");
    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    let (log_val, gas) = write_log.read(&key);
    vp_add_gas(env, gas);
    match log_val {
        Some(&write_log::StorageModification::Write { ref value }) => {
            let len: i64 =
                value.len().try_into().expect("data length overflow");
            let gas = env
                .memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
            vp_add_gas(env, gas);
            len
        }
        Some(&write_log::StorageModification::Delete) => {
            // fail, given key has been deleted
            -1
        }
        Some(&write_log::StorageModification::InitAccount {
            ref vp, ..
        }) => {
            // read the VP of a new account
            let len: i64 = vp.len() as _;
            let gas = env
                .memory
                .write_bytes(result_ptr, vp)
                .expect("cannot write to memory");
            vp_add_gas(env, gas);
            len
        }
        None => {
            // when not found in write log, try to read from the storage
            let storage: &Storage = unsafe { &*(env.storage.get()) };
            let (value, gas) = storage.read(&key).expect("storage read failed");
            vp_add_gas(env, gas);
            match value {
                Some(value) => {
                    let len: i64 =
                        value.len().try_into().expect("data length overflow");
                    let gas = env
                        .memory
                        .write_bytes(result_ptr, value)
                        .expect("cannot write to memory");
                    vp_add_gas(env, gas);
                    len
                }
                None => {
                    // fail, key not found
                    -1
                }
            }
        }
    }
}

/// Storage `has_key` in prior state (before tx execution) function exposed to
/// the wasm VM VP environment. It will try to read from the storage.
fn vp_storage_has_key_pre(env: &VpEnv, key_ptr: u64, key_len: u64) -> u64 {
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    vp_add_gas(env, gas);

    log::debug!("vp_storage_has_key_pre {}, key {}", key, key_ptr,);

    let key = Key::parse(key).expect("Cannot parse the key string");

    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let (present, gas) = storage.has_key(&key).expect("storage has_key failed");
    vp_add_gas(env, gas);
    if present { 1 } else { 0 }
}

/// Storage `has_key` in posterior state (after tx execution) function exposed
/// to the wasm VM VP environment. It will
/// try to check the write log first and if no entry found then the storage.
fn vp_storage_has_key_post(env: &VpEnv, key_ptr: u64, key_len: u64) -> u64 {
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    vp_add_gas(env, gas);

    log::debug!("vp_storage_has_key_post {}, key {}", key, key_ptr,);

    let key = Key::parse(key).expect("Cannot parse the key string");

    // try to read from the write log first
    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    let (log_val, gas) = write_log.read(&key);
    vp_add_gas(env, gas);
    match log_val {
        Some(&write_log::StorageModification::Write { .. }) => 1,
        Some(&write_log::StorageModification::Delete) => {
            // the given key has been deleted
            0
        }
        Some(&write_log::StorageModification::InitAccount { .. }) => 1,
        None => {
            // when not found in write log, try to check the storage
            let storage: &Storage = unsafe { &*(env.storage.get()) };
            let (present, gas) =
                storage.has_key(&key).expect("storage has_key failed");
            vp_add_gas(env, gas);
            if present { 1 } else { 0 }
        }
    }
}

/// Storage prefix iterator function exposed to the wasm VM VP environment.
/// It will try to get an iterator from the storage and return the corresponding
/// ID of the interator.
fn vp_storage_iter_prefix(
    env: &VpEnv,
    prefix_ptr: u64,
    prefix_len: u64,
) -> u64 {
    let (prefix, gas) = env
        .memory
        .read_string(prefix_ptr, prefix_len as _)
        .expect("Cannot read the prefix from memory");
    vp_add_gas(env, gas);

    log::debug!("vp_storage_iter_prefix {}, prefix {}", prefix, prefix_ptr);

    let prefix = Key::parse(prefix).expect("Cannot parse the prefix string");

    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let iterators: &mut PrefixIterators =
        unsafe { &mut *(env.iterators.get()) };
    let (iter, gas) = storage.iter_prefix(&prefix);
    vp_add_gas(env, gas);
    iterators.insert(iter).id()
}

/// Storage prefix iterator next (before tx execution) function exposed to the
/// wasm VM VP environment. It will read a key value pair from the storage.
fn vp_storage_iter_pre_next(env: &VpEnv, iter_id: u64, result_ptr: u64) -> u64 {
    log::debug!(
        "vp_storage_iter_pre_next iter_id {}, result_ptr {}",
        iter_id,
        result_ptr,
    );

    let iterators: &mut PrefixIterators =
        unsafe { &mut *(env.iterators.get()) };
    let iter_id = PrefixIteratorId::new(iter_id);
    if let Some((key, val, gas)) = iterators.next(iter_id) {
        vp_add_gas(env, gas);
        let key_val = KeyVal { key, val }
            .try_to_vec()
            .expect("cannot serialize the key value pair");
        let gas = env
            .memory
            .write_bytes(result_ptr, key_val)
            .expect("cannot write to memory");
        vp_add_gas(env, gas);
        return 1;
    }
    // key not found
    0
}

/// Storage prefix iterator next (after tx execution) function exposed to the
/// wasm VM VP environment. It will read a key value pair from the write log
/// first and if no entry found then from the storage.
fn vp_storage_iter_post_next(
    env: &VpEnv,
    iter_id: u64,
    result_ptr: u64,
) -> u64 {
    log::debug!(
        "vp_storage_iter_post_next iter_id {}, result_ptr {}",
        iter_id,
        result_ptr,
    );

    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    let iterators: &mut PrefixIterators =
        unsafe { &mut *(env.iterators.get()) };
    let iter_id = PrefixIteratorId::new(iter_id);
    while let Some((key, val, iter_gas)) = iterators.next(iter_id) {
        let (log_val, log_gas) = write_log.read(
            &Key::parse(key.clone()).expect("Cannot parse the key string"),
        );
        vp_add_gas(env, iter_gas + log_gas);
        match log_val {
            Some(&write_log::StorageModification::Write { ref value }) => {
                let key_val = KeyVal {
                    key,
                    val: value.clone(),
                }
                .try_to_vec()
                .expect("cannot serialize the key value pair");
                let gas = env
                    .memory
                    .write_bytes(result_ptr, key_val)
                    .expect("cannot write to memory");
                vp_add_gas(env, gas);
                return 1;
            }
            Some(&write_log::StorageModification::Delete) => {
                // check the next because the key has already deleted
                continue;
            }
            Some(&write_log::StorageModification::InitAccount { .. }) => {
                // a VP of a new account doesn't need to be iterated
                continue;
            }
            None => {
                let key_val = KeyVal { key, val }
                    .try_to_vec()
                    .expect("cannot serialize the key value pair");
                let gas = env
                    .memory
                    .write_bytes(result_ptr, key_val)
                    .expect("cannot write to memory");
                vp_add_gas(env, gas);
                return 1;
            }
        }
    }
    // key not found
    0
}

/// Storage prefix iterator for prior state (before tx execution) function
/// exposed to the wasm VM VP environment. It will try to read from the storage.
///
/// Returns [`-1`] when the key is not present, or the length of the data when
/// the key is present (the length may be [`0`]).
fn vp_storage_iter_pre_next_varlen(
    env: &VpEnv,
    iter_id: u64,
    result_ptr: u64,
) -> i64 {
    log::debug!(
        "vp_storage_iter_pre_next_varlen iter_id {}, result_ptr {}",
        iter_id,
        result_ptr,
    );

    let iterators: &mut PrefixIterators =
        unsafe { &mut *(env.iterators.get()) };
    let iter_id = PrefixIteratorId::new(iter_id);
    if let Some((key, val, gas)) = iterators.next(iter_id) {
        vp_add_gas(env, gas);
        let key_val = KeyVal { key, val }
            .try_to_vec()
            .expect("cannot serialize the key value pair");
        let len: i64 = key_val.len().try_into().expect("data length overflow");
        let gas = env
            .memory
            .write_bytes(result_ptr, key_val)
            .expect("cannot write to memory");
        vp_add_gas(env, gas);
        return len;
    }
    // key not found
    -1
}

/// Storage prefix iterator next for posterior state (after tx execution)
/// function exposed to the wasm VM VP environment. It will try to read from the
/// write log first and if no entry found then from the storage.
///
/// Returns [`-1`] when the key is not present, or the length of the data when
/// the key is present (the length may be [`0`]).
fn vp_storage_iter_post_next_varlen(
    env: &VpEnv,
    iter_id: u64,
    result_ptr: u64,
) -> i64 {
    log::debug!(
        "vp_storage_iter_post_next_varlen iter_id {}, result_ptr {}",
        iter_id,
        result_ptr,
    );

    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    let iterators: &mut PrefixIterators =
        unsafe { &mut *(env.iterators.get()) };
    let iter_id = PrefixIteratorId::new(iter_id);
    while let Some((key, val, iter_gas)) = iterators.next(iter_id) {
        let (log_val, log_gas) = write_log.read(
            &Key::parse(key.clone()).expect("Cannot parse the key string"),
        );
        vp_add_gas(env, iter_gas + log_gas);
        match log_val {
            Some(&write_log::StorageModification::Write { ref value }) => {
                let key_val = KeyVal {
                    key,
                    val: value.clone(),
                }
                .try_to_vec()
                .expect("cannot serialize the key value pair");
                let len: i64 =
                    key_val.len().try_into().expect("data length overflow");
                let gas = env
                    .memory
                    .write_bytes(result_ptr, key_val)
                    .expect("cannot write to memory");
                vp_add_gas(env, gas);
                return len;
            }
            Some(&write_log::StorageModification::Delete) => {
                // check the next because the key has already deleted
                continue;
            }
            Some(&write_log::StorageModification::InitAccount { .. }) => {
                // a VP of a new account doesn't need to be iterated
                continue;
            }
            None => {
                let key_val = KeyVal { key, val }
                    .try_to_vec()
                    .expect("cannot serialize the key value pair");
                let len: i64 =
                    key_val.len().try_into().expect("data length overflow");
                let gas = env
                    .memory
                    .write_bytes(result_ptr, key_val)
                    .expect("cannot write to memory");
                vp_add_gas(env, gas);
                return len;
            }
        }
    }
    // key not found
    -1
}

/// Verifier insertion function exposed to the wasm VM Tx environment.
fn tx_insert_verifier(env: &TxEnv, addr_ptr: u64, addr_len: u64) {
    let (addr, gas) = env
        .memory
        .read_string(addr_ptr, addr_len as _)
        .expect("Cannot read the key from memory");
    tx_add_gas(env, gas);

    log::debug!("tx_insert_verifier {}, addr_ptr {}", addr, addr_ptr,);

    let addr =
        RawAddress::parse(addr).expect("Cannot parse the address string");

    let verifiers: &mut HashSet<Address> =
        unsafe { &mut *(env.verifiers.get()) };
    verifiers.insert(addr.hash());
    tx_add_gas(env, addr_len);
}

/// Update a validity predicate function exposed to the wasm VM Tx environment
fn tx_update_validity_predicate(
    env: &TxEnv,
    addr_ptr: u64,
    addr_len: u64,
    code_ptr: u64,
    code_len: u64,
) {
    let (addr, gas) = env
        .memory
        .read_string(addr_ptr, addr_len as _)
        .expect("Cannot read the address from memory");
    log::debug!(
        "tx_update_validity_predicate {}, addr_ptr {}",
        addr,
        addr_ptr
    );
    tx_add_gas(env, gas);

    let key = Key::parse(addr)
        .expect("Cannot parse the address")
        .push(&"?".to_owned())
        .expect("Cannot make the key for the VP");
    let (code, gas) = env
        .memory
        .read_bytes(code_ptr, code_len as _)
        .expect("Cannot read the VP code");
    tx_add_gas(env, gas);

    let write_log: &mut WriteLog = unsafe { &mut *(env.write_log.get()) };
    let (gas, _size_diff) = write_log.write(&key, code);
    tx_add_gas(env, gas);
    // TODO: charge the size diff
}

/// Try to initialize a new account with a given address. The action must be
/// authorized by the parent address.
fn tx_init_account(
    env: &TxEnv,
    addr_ptr: u64,
    addr_len: u64,
    code_ptr: u64,
    code_len: u64,
) {
    let (addr, gas) = env
        .memory
        .read_string(addr_ptr, addr_len as _)
        .expect("Cannot read the address from memory");
    tx_add_gas(env, gas);
    let (code, gas) = env
        .memory
        .read_bytes(code_ptr, code_len as _)
        .expect("Cannot read validity predicate from memory");
    tx_add_gas(env, gas);

    let addr =
        RawAddress::parse(addr).expect("Cannot parse the address string");
    let parent_addr = addr.parent();
    let parent_addr_hash = parent_addr.hash();

    log::debug!("tx_init_account address: {}, parent: {}", addr, parent_addr);

    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let (parent_exists, gas) = storage
        .exists(&parent_addr_hash)
        .expect("Cannot read storage");
    tx_add_gas(env, gas);
    // If the parent address doesn't exist, the tx will be declined
    if !parent_exists {
        log::warn!(
            "Cannot initialize an account address {}, because the parent \
             address {} doesn't exist",
            addr,
            parent_addr
        );
        unreachable!()
    }
    let write_log: &mut WriteLog = unsafe { &mut *(env.write_log.get()) };
    let gas = write_log.init_account(addr.hash(), parent_addr_hash, code);

    // ensure that the parent address verifies the account creation
    let verifiers: &mut HashSet<Address> =
        unsafe { &mut *(env.verifiers.get()) };
    verifiers.insert(parent_addr.hash());
    tx_add_gas(env, gas);
}

/// Getting the chain ID function exposed to the wasm VM Tx environment.
fn tx_get_chain_id(env: &TxEnv, result_ptr: u64) {
    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let (chain_id, gas) = storage.get_chain_id();
    tx_add_gas(env, gas);
    let gas = env
        .memory
        .write_string(result_ptr, chain_id)
        .expect("cannot write to memory");
    tx_add_gas(env, gas);
}

/// Getting the block height function exposed to the wasm VM Tx
/// environment. The height is that of the block to which the current
/// transaction is being applied.
fn tx_get_block_height(env: &TxEnv) -> u64 {
    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let (height, gas) = storage.get_block_height();
    tx_add_gas(env, gas);
    height.0
}

/// Getting the block hash function exposed to the wasm VM Tx environment. The
/// hash is that of the block to which the current transaction is being applied.
fn tx_get_block_hash(env: &TxEnv, result_ptr: u64) {
    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let (hash, gas) = storage.get_block_hash();
    tx_add_gas(env, gas);
    let gas = env
        .memory
        .write_bytes(result_ptr, hash.0)
        .expect("cannot write to memory");
    tx_add_gas(env, gas);
}

/// Getting the chain ID function exposed to the wasm VM VP environment.
fn vp_get_chain_id(env: &VpEnv, result_ptr: u64) {
    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let (chain_id, gas) = storage.get_chain_id();
    vp_add_gas(env, gas);
    let gas = env
        .memory
        .write_string(result_ptr, chain_id)
        .expect("cannot write to memory");
    vp_add_gas(env, gas);
}

/// Getting the block height function exposed to the wasm VM VP
/// environment. The height is that of the block to which the current
/// transaction is being applied.
fn vp_get_block_height(env: &VpEnv) -> u64 {
    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let (height, gas) = storage.get_block_height();
    vp_add_gas(env, gas);
    height.0
}

/// Getting the block hash function exposed to the wasm VM VP environment. The
/// hash is that of the block to which the current transaction is being applied.
fn vp_get_block_hash(env: &VpEnv, result_ptr: u64) {
    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let (hash, gas) = storage.get_block_hash();
    vp_add_gas(env, gas);
    let gas = env
        .memory
        .write_bytes(result_ptr, hash.0)
        .expect("cannot write to memory");
    vp_add_gas(env, gas);
}

fn vp_verify_tx_signature(
    env: &VpEnv,
    pk_ptr: u64,
    pk_len: u64,
    data_ptr: u64,
    data_len: u64,
    sig_ptr: u64,
    sig_len: u64,
) -> u64 {
    let (pk, gas) = env
        .memory
        .read_bytes(pk_ptr, pk_len as _)
        .expect("Cannot read public key from memory");
    vp_add_gas(env, gas);
    let pk: PublicKey =
        BorshDeserialize::try_from_slice(&pk).expect("Canot decode public key");

    let (data, gas) = env
        .memory
        .read_bytes(data_ptr, data_len as _)
        .expect("Cannot read signature data from memory");
    vp_add_gas(env, gas);

    let (sig, gas) = env
        .memory
        .read_bytes(sig_ptr, sig_len as _)
        .expect("Cannot read signature from memory");
    vp_add_gas(env, gas);
    let sig: Signature =
        BorshDeserialize::try_from_slice(&sig).expect("Canot decode signature");

    vp_add_gas(env, (data.len() + env.tx_code.len()) as _);
    let signature_data = [data.clone(), env.tx_code.clone()].concat();
    if verify_signature_raw(&pk, &signature_data, &sig).is_ok() {
        1
    } else {
        0
    }
}

/// Log a string from exposed to the wasm VM Tx environment. The message will be
/// printed at the [`log::Level::Info`]. This function is for development only.
fn tx_log_string(env: &TxEnv, str_ptr: u64, str_len: u64) {
    let (str, _gas) = env
        .memory
        .read_string(str_ptr, str_len as _)
        .expect("Cannot read the string from memory");

    log::info!("WASM Transaction log: {}", str);
}

/// Log a string from exposed to the wasm VM matchmaker environment. The message
/// will be printed at the [`log::Level::Info`]. This function is for
/// development only.
fn matchmaker_log_string(env: &MatchmakerEnv, str_ptr: u64, str_len: u64) {
    let (str, _gas) = env
        .memory
        .read_string(str_ptr, str_len as _)
        .expect("Cannot read the string from memory");

    log::info!("WASM Matchmaker log: {}", str);
}

/// Log a string from exposed to the wasm VM VP environment. The message will be
/// printed at the [`log::Level::Info`]. This function is for development only.
fn vp_log_string(env: &VpEnv, str_ptr: u64, str_len: u64) {
    let (str, _gas) = env
        .memory
        .read_string(str_ptr, str_len as _)
        .expect("Cannot read the string from memory");

    log::info!("WASM Validity predicate log: {}", str);
}

/// Inject a transaction from matchmaker's matched intents to the ledger
fn send_match(env: &MatchmakerEnv, data_ptr: u64, data_len: u64) {
    let inject_tx: &Sender<Tx> = &env.inject_tx;
    let (tx_data, _gas) = env
        .memory
        .read_bytes(data_ptr, data_len as _)
        .expect("Cannot read the key from memory");
    let tx = Tx {
        code: env.tx_code.clone(),
        data: Some(tx_data),
    };
    inject_tx.try_send(tx).expect("failed to send tx")
}
