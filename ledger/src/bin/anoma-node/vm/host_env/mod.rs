pub mod write_log;

use std::convert::TryInto;

use anoma::protobuf::types::Tx;
use tokio::sync::mpsc::Sender;
use wasmer::{
    HostEnvInitError, ImportObject, Instance, Memory, Store, WasmerEnv,
};

use self::write_log::WriteLog;
use super::memory::AnomaMemory;
use super::{TxEnvHostWrapper, VpEnvHostWrapper};
use crate::shell::storage::{self, Address, Storage};

#[derive(Clone)]
struct TxEnv {
    // not thread-safe, assuming single-threaded Tx runner
    storage: TxEnvHostWrapper<Storage>,
    // not thread-safe, assuming single-threaded Tx runner
    write_log: TxEnvHostWrapper<WriteLog>,
    memory: AnomaMemory,
}

impl WasmerEnv for TxEnv {
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

#[derive(Clone)]
struct VpEnv {
    /// The address of the account that owns the VP
    addr: Address,
    // not thread-safe, assuming read-only access from parallel Vp runners
    storage: VpEnvHostWrapper<Storage>,
    // not thread-safe, assuming read-only access from parallel Vp runners
    write_log: VpEnvHostWrapper<WriteLog>,
    memory: AnomaMemory,
}

impl WasmerEnv for VpEnv {
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

#[derive(Clone)]
pub struct MatchmakerEnv {
    // not thread-safe, assuming single-threaded Tx runner
    // pub ledger: TxShellWrapper,
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
    storage: TxEnvHostWrapper<Storage>,
    write_log: TxEnvHostWrapper<WriteLog>,
    initial_memory: Memory,
) -> ImportObject {
    let tx_env = TxEnv {
        storage,
        write_log,
        memory: AnomaMemory::default(),
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "read" => wasmer::Function::new_native_with_env(wasm_store, tx_env.clone(), tx_storage_read),
            "write" => wasmer::Function::new_native_with_env(wasm_store, tx_env.clone(), tx_storage_write),
            "delete" => wasmer::Function::new_native_with_env(wasm_store, tx_env.clone(), tx_storage_delete),
            "read_varlen" => wasmer::Function::new_native_with_env(wasm_store, tx_env.clone(), tx_storage_read_varlen),
            "log_string" => wasmer::Function::new_native_with_env(wasm_store, tx_env, tx_log_string),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// validity predicate code
pub fn prepare_vp_imports(
    wasm_store: &Store,
    addr: Address,
    storage: VpEnvHostWrapper<Storage>,
    write_log: VpEnvHostWrapper<WriteLog>,
    initial_memory: Memory,
) -> ImportObject {
    let vp_env = VpEnv {
        addr,
        storage,
        write_log,
        memory: AnomaMemory::default(),
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "read_pre" => wasmer::Function::new_native_with_env(wasm_store, vp_env.clone(), vp_storage_read_pre),
            "read_post" => wasmer::Function::new_native_with_env(wasm_store, vp_env.clone(), vp_storage_read_post),
            "read_pre_varlen" => wasmer::Function::new_native_with_env(wasm_store, vp_env.clone(), vp_storage_read_pre_varlen),
            "read_post_varlen" => wasmer::Function::new_native_with_env(wasm_store, vp_env.clone(), vp_storage_read_post_varlen),
            "log_string" => wasmer::Function::new_native_with_env(wasm_store, vp_env, vp_log_string),
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
            "send_match" => wasmer::Function::new_native_with_env(wasm_store,
                                                                  env.clone(),
                                                                  send_match),
            "log_string" => wasmer::Function::new_native_with_env(wasm_store,
                                                                  env,
                                                                  matchmaker_log_string),
        },
    }
}

fn parse_key(key: String) -> (storage::Address, String) {
    // parse the address from the first key segment and get the rest of the key
    let mut key_segments: Vec<&str> = key.split('/').collect();
    let addr_str = key_segments
        .first()
        .expect("key shouldn't be empty")
        .to_string();
    key_segments.drain(0..1);
    let key = key_segments.join("/");
    let addr: storage::Address =
        storage::KeySeg::from_key_seg(&addr_str).expect("should be an address");
    (addr, key)
}

/// Storage read function exposed to the wasm VM Tx environment. It will try to
/// read from the write log first and if no entry found then from the storage.
fn tx_storage_read(
    env: &TxEnv,
    key_ptr: u64,
    key_len: u64,
    result_ptr: u64,
) -> u64 {
    let key = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");

    log::debug!(
        "tx_storage_read {}, key {}, result_ptr {}",
        key,
        key_ptr,
        result_ptr,
    );

    let (addr, key) = parse_key(key);

    // try to read from the write log first
    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    match write_log.read(&addr, &key) {
        Some(&write_log::StorageModification::Write { ref value }) => {
            env.memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
            return 1;
        }
        Some(&write_log::StorageModification::Delete) => {
            // fail, given key has been deleted
            return 0;
        }
        None => {
            // when not found in write log, try to read from the storage
            let storage: &Storage = unsafe { &*(env.storage.get()) };
            let (value, _gas) =
                storage.read(&addr, &key).expect("storage read failed");
            match value {
                Some(value) => {
                    env.memory
                        .write_bytes(result_ptr, value)
                        .expect("cannot write to memory");
                    return 1;
                }
                None => {
                    // fail, key not found
                    return 0;
                }
            }
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
    let key = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");

    log::debug!(
        "tx_storage_read {}, key {}, result_ptr {}",
        key,
        key_ptr,
        result_ptr,
    );

    let (addr, key) = parse_key(key);

    // try to read from the write log first
    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    match write_log.read(&addr, &key) {
        Some(&write_log::StorageModification::Write { ref value }) => {
            let len: i64 =
                value.len().try_into().expect("data length overflow");
            env.memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
            len
        }
        Some(&write_log::StorageModification::Delete) => {
            // fail, given key has been deleted
            -1
        }
        None => {
            // when not found in write log, try to read from the storage
            let storage: &Storage = unsafe { &*(env.storage.get()) };
            let (value, _gas) =
                storage.read(&addr, &key).expect("storage read failed");
            match value {
                Some(value) => {
                    let len: i64 =
                        value.len().try_into().expect("data length overflow");
                    env.memory
                        .write_bytes(result_ptr, value)
                        .expect("cannot write to memory");
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

/// Storage write function exposed to the wasm VM Tx environment. The given
/// key/value will be written to the write log.
fn tx_storage_write(
    env: &TxEnv,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
) -> u64 {
    let key = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    let value = env
        .memory
        .read_bytes(val_ptr, val_len as _)
        .expect("Cannot read the value from memory");

    log::debug!("tx_storage_update {}, {:#?}", key, value);

    let (addr, key) = parse_key(key);

    let write_log: &mut WriteLog = unsafe { &mut *(env.write_log.get()) };
    write_log.write(addr, key, value);

    1
}

/// Storage delete function exposed to the wasm VM Tx environment. The given
/// key/value will be written as deleted to the write log.
fn tx_storage_delete(env: &TxEnv, key_ptr: u64, key_len: u64) -> u64 {
    let key = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");

    log::debug!("tx_storage_delete {}", key);

    let (addr, key) = parse_key(key);

    let write_log: &mut WriteLog = unsafe { &mut *(env.write_log.get()) };
    write_log.delete(addr, key);

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
    let key = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");

    // try to read from the storage
    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let (value, _gas) =
        storage.read(&env.addr, &key).expect("storage read failed");
    log::debug!(
        "vp_storage_read_pre addr {}, key {}, value {:#?}",
        env.addr,
        key,
        value,
    );
    match value {
        Some(value) => {
            env.memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
            return 1;
        }
        None => {
            // fail, key not found
            return 0;
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
    let key = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");

    log::debug!(
        "vp_storage_read_post {}, key {}, result_ptr {}",
        key,
        key_ptr,
        result_ptr,
    );

    // try to read from the write log first
    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    match write_log.read(&env.addr, &key) {
        Some(&write_log::StorageModification::Write { ref value }) => {
            env.memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
            return 1;
        }
        Some(&write_log::StorageModification::Delete) => {
            // fail, given key has been deleted
            return 0;
        }
        None => {
            // when not found in write log, try to read from the storage
            let storage: &Storage = unsafe { &*(env.storage.get()) };
            let (value, _gas) =
                storage.read(&env.addr, &key).expect("storage read failed");
            match value {
                Some(value) => {
                    env.memory
                        .write_bytes(result_ptr, value)
                        .expect("cannot write to memory");
                    return 1;
                }
                None => {
                    // fail, key not found
                    return 0;
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
    let key = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");

    // try to read from the storage
    let storage: &Storage = unsafe { &*(env.storage.get()) };
    let (value, _gas) =
        storage.read(&env.addr, &key).expect("storage read failed");
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
            env.memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
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
    let key = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");

    log::debug!(
        "vp_storage_read_post {}, key {}, result_ptr {}",
        key,
        key_ptr,
        result_ptr,
    );

    // try to read from the write log first
    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    match write_log.read(&env.addr, &key) {
        Some(&write_log::StorageModification::Write { ref value }) => {
            let len: i64 =
                value.len().try_into().expect("data length overflow");
            env.memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
            len
        }
        Some(&write_log::StorageModification::Delete) => {
            // fail, given key has been deleted
            -1
        }
        None => {
            // when not found in write log, try to read from the storage
            let storage: &Storage = unsafe { &*(env.storage.get()) };
            let (value, _gas) =
                storage.read(&env.addr, &key).expect("storage read failed");
            match value {
                Some(value) => {
                    let len: i64 =
                        value.len().try_into().expect("data length overflow");
                    env.memory
                        .write_bytes(result_ptr, value)
                        .expect("cannot write to memory");
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

/// Log a string from exposed to the wasm VM Tx environment. The message will be
/// printed at the [`log::Level::Info`].
fn tx_log_string(env: &TxEnv, str_ptr: u64, str_len: u64) {
    let str = env
        .memory
        .read_string(str_ptr, str_len as _)
        .expect("Cannot read the string from memory");

    log::info!("WASM Transaction log: {}", str);
}

/// Log a string from exposed to the wasm VM matchmaker environment. The message
/// will be printed at the [`log::Level::Info`].
fn matchmaker_log_string(env: &MatchmakerEnv, str_ptr: u64, str_len: u64) {
    let str = env
        .memory
        .read_string(str_ptr, str_len as _)
        .expect("Cannot read the string from memory");

    log::info!("WASM Matchmaker log: {}", str);
}

/// Log a string from exposed to the wasm VM VP environment. The message will be
/// printed at the [`log::Level::Info`].
fn vp_log_string(env: &VpEnv, str_ptr: u64, str_len: u64) {
    let str = env
        .memory
        .read_string(str_ptr, str_len as _)
        .expect("Cannot read the string from memory");

    log::info!("WASM Validity predicate log: {}", str);
}

fn send_match(env: &MatchmakerEnv, data_ptr: u64, data_len: u64) {
    let inject_tx: &Sender<Tx> = &env.inject_tx;
    let tx_data = env
        .memory
        .read_bytes(data_ptr, data_len as _)
        .expect("Cannot read the key from memory");
    let tx = Tx {
        code: env.tx_code.clone(),
        data: Some(tx_data),
    };
    inject_tx.try_send(tx).expect("failed to send tx")
}
