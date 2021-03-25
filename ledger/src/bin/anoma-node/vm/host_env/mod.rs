pub mod write_log;

use self::write_log::WriteLog;

use super::TxEnvHostWrapper;
use super::{memory::AnomaMemory, VpEnvHostWrapper};
use crate::shell::storage::{self, Storage};
use wasmer::{
    HostEnvInitError, ImportObject, Instance, Memory, Store, WasmerEnv,
};

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
            "write" => wasmer::Function::new_native_with_env(wasm_store, tx_env, tx_storage_write),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// validity predicate code
pub fn prepare_vp_imports(
    _wasm_store: &Store,
    storage: VpEnvHostWrapper<Storage>,
    write_log: VpEnvHostWrapper<WriteLog>,
    initial_memory: Memory,
) -> ImportObject {
    let _vp_env = VpEnv {
        storage,
        write_log,
        memory: AnomaMemory::default(),
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
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
        "vm_storage_read {}, key {}, result_ptr {}",
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

    log::debug!("vm_storage_update {}, {:#?}", key, value);

    let (addr, key) = parse_key(key);

    let write_log: &mut WriteLog = unsafe { &mut *(env.write_log.get()) };
    write_log.write(addr, key, value);

    1
}
