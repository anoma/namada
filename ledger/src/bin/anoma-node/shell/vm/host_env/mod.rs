mod write_log;

use super::TxStorageWrapper;
use super::{
    super::{storage, Storage},
    memory::AnomaMemory,
};
use wasmer::{
    HostEnvInitError, ImportObject, Instance, Memory, Store, WasmerEnv,
};

#[derive(Clone)]
struct TxEnv {
    // not thread-safe, assuming single-threaded Tx runner
    ledger: TxStorageWrapper,
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
    ledger: TxStorageWrapper,
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
    memory: Memory,
    ledger: TxStorageWrapper,
) -> ImportObject {
    let tx_env = TxEnv {
        ledger,
        memory: AnomaMemory::default(),
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => memory,
            "read" => wasmer::Function::new_native_with_env(wasm_store, tx_env.clone(), storage_read),
            "update" => wasmer::Function::new_native_with_env(wasm_store, tx_env, storage_update),
        },
    }
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// validity predicate code
pub fn prepare_vp_imports(_wasm_store: &Store, memory: Memory) -> ImportObject {
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => memory,
        },
    }
}

/// Storage read function exposed to the wasm VM environment
fn storage_read(
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

    let storage: &mut Storage =
        unsafe { &mut *(env.ledger.get() as *mut Storage) };
    let keys = key.split('/').collect::<Vec<&str>>();
    if let [key_a, key_b, key_c] = keys.as_slice() {
        if "balance" == key_b.to_string() {
            let addr: storage::Address =
                storage::KeySeg::from_key_seg(&key_a.to_string())
                    .expect("should be an address");
            let key = format!("{}/{}", key_b, key_c);
            let value = storage
                .read(&addr, &key)
                .expect("storage read failed")
                .expect("key not found");
            env.memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
            return 1;
        }
    }
    // fail
    0
}

/// Storage update function exposed to the wasm VM environment
fn storage_update(
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
    let val = env
        .memory
        .read_bytes(val_ptr, val_len as _)
        .expect("Cannot read the value from memory");
    log::debug!("vm_storage_update {}, {:#?}", key, val);

    let storage: &mut Storage =
        unsafe { &mut *(env.ledger.get() as *mut Storage) };
    let keys = key.split('/').collect::<Vec<&str>>();
    if let [key_a, key_b, key_c] = keys.as_slice() {
        if "balance" == key_b.to_string() {
            let addr: storage::Address =
                storage::KeySeg::from_key_seg(&key_a.to_string())
                    .expect("should be an address");
            let key = format!("{}/{}", key_b, key_c);
            storage
                .write(&addr, &key, val)
                .expect("VM storage write fail");
            return 1;
        }
    }
    // fail
    0
}
