pub mod prefix_iter;
pub mod write_log;

use std::collections::HashSet;
use std::convert::TryInto;

use anoma_shared::types::key::ed25519::{
    verify_signature_raw, PublicKey, Signature, SignedTxData,
};
use anoma_shared::types::{Address, Key};
use anoma_shared::vm_memory::KeyVal;
use borsh::{BorshDeserialize, BorshSerialize};
use tokio::sync::mpsc::Sender;
use wasmer::{
    HostEnvInitError, ImportObject, Instance, Memory, Store, WasmerEnv,
};

use self::prefix_iter::{PrefixIteratorId, PrefixIterators};
use self::write_log::WriteLog;
use super::memory::AnomaMemory;
use super::{EnvHostSliceWrapper, EnvHostWrapper, MutEnvHostWrapper};
use crate::node::shell::gas::{BlockGasMeter, VpGasMeter};
use crate::node::shell::storage::{self, Storage};
use crate::node::vm::VpRunner;
use crate::proto::types::Tx;
use crate::types::MatchmakerMessage;
use crate::wallet;

const VERIFY_TX_SIG_GAS_COST: u64 = 1000;
const WASM_VALIDATION_GAS_PER_BYTE: u64 = 1;

struct TxEnv<'a, DB>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    storage: EnvHostWrapper<'a, &'a Storage<DB>>,
    // not thread-safe, assuming single-threaded Tx runner
    write_log: MutEnvHostWrapper<WriteLog>,
    // not thread-safe, assuming single-threaded Tx runner
    iterators: MutEnvHostWrapper<PrefixIterators<'static, DB>>,
    // not thread-safe, assuming single-threaded Tx runner
    verifiers: MutEnvHostWrapper<HashSet<Address>>,
    // not thread-safe, assuming single-threaded Tx runner
    gas_meter: MutEnvHostWrapper<BlockGasMeter>,
    memory: AnomaMemory,
}

// We have to implement the `Clone` instance manually, because we cannot
// implement `DB: Clone` which is required by `WasmerEnv`, but we don't store
// the `DB` directly here, so we don't need to. Instead, we store the reference
// to `DB` inside the `EnvHostWrapper` which is safe to clone.
impl<DB> Clone for TxEnv<'_, DB>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            write_log: self.write_log.clone(),
            iterators: self.iterators.clone(),
            verifiers: self.verifiers.clone(),
            gas_meter: self.gas_meter.clone(),
            memory: self.memory.clone(),
        }
    }
}

impl<DB> WasmerEnv for TxEnv<'_, DB>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

// VpEnv is parameterized over DB to allow testing
pub struct VpEnv<'a, DB>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    /// The address of the account that owns the VP
    pub addr: Address,
    /// this is not thread-safe, but because each VP has its own instance there
    /// is no shared access
    iterators: MutEnvHostWrapper<PrefixIterators<'static, DB>>,
    /// thread-safe read-only access from parallel Vp runners
    storage: EnvHostWrapper<'a, &'a Storage<DB>>,
    /// thread-safe read-only access from parallel Vp runners
    write_log: EnvHostWrapper<'a, &'a WriteLog>,
    // TODO In parallel runs, we can change only the maximum used gas of all
    /// the VPs that we ran.
    gas_meter: MutEnvHostWrapper<VpGasMeter>,
    /// The transaction code is used for signature verification
    tx_code: EnvHostSliceWrapper<'a, &'a [u8]>,
    /// Change storage keys, we use these for `eval` invocations
    pub keys_changed: EnvHostSliceWrapper<'a, &'a [Key]>,
    /// Addresses of transaction verifiers, we use these for `eval` invocations
    pub verifiers: EnvHostWrapper<'a, &'a HashSet<Address>>,
    memory: AnomaMemory,
}

// We have to implement the `Clone` instance manually, because we cannot
// implement `DB: Clone` which is required by `WasmerEnv`, but we don't store
// the `DB` directly here, so we don't need to. Instead, we store the reference
// to `DB` inside the `EnvHostWrapper` which is safe to clone.
impl<'a, DB> Clone for VpEnv<'a, DB>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    fn clone(&self) -> Self {
        Self {
            addr: self.addr.clone(),
            iterators: self.iterators.clone(),
            storage: self.storage.clone(),
            write_log: self.write_log.clone(),
            gas_meter: self.gas_meter.clone(),
            tx_code: self.tx_code.clone(),
            keys_changed: self.keys_changed.clone(),
            verifiers: self.verifiers.clone(),
            memory: self.memory.clone(),
        }
    }
}

impl<'a, DB> WasmerEnv for VpEnv<'a, DB>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
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
    pub inject_mm_message: Sender<MatchmakerMessage>,
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

#[derive(Clone)]
pub struct FilterEnv {
    pub memory: AnomaMemory,
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
pub fn prepare_tx_imports<DB>(
    wasm_store: &Store,
    storage: EnvHostWrapper<'static, &Storage<DB>>,
    write_log: MutEnvHostWrapper<WriteLog>,
    iterators: MutEnvHostWrapper<PrefixIterators<'static, DB>>,
    verifiers: MutEnvHostWrapper<HashSet<Address>>,
    gas_meter: MutEnvHostWrapper<BlockGasMeter>,
    initial_memory: Memory,
) -> ImportObject
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
{
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

            // These functions must still be compatible with the wasm interface
            // They must match exactly the C fn, except we prepend the env arg
            "gas" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_charge_gas),
            "_read" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_read),
            "_has_key" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_has_key),
            "_write" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_write),
            "_delete" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_delete),
            "_iter_prefix" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_iter_prefix),
            "_iter_next" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), tx_storage_iter_next),
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

/// Construct environment and then prepare imports
#[allow(clippy::too_many_arguments)]
pub fn prepare_vp_env<DB>(
    wasm_store: &Store,
    addr: Address,
    storage: EnvHostWrapper<'static, &'static Storage<DB>>,
    write_log: EnvHostWrapper<'static, &WriteLog>,
    iterators: MutEnvHostWrapper<PrefixIterators<'static, DB>>,
    gas_meter: MutEnvHostWrapper<VpGasMeter>,
    tx_code: EnvHostSliceWrapper<'static, &[u8]>,
    initial_memory: Memory,
    keys_changed: EnvHostSliceWrapper<'static, &[Key]>,
    verifiers: EnvHostWrapper<'static, &'static HashSet<Address>>,
) -> ImportObject
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let env = VpEnv {
        addr,
        storage,
        write_log,
        iterators,
        gas_meter,
        tx_code,
        keys_changed,
        verifiers,
        memory: AnomaMemory::default(),
    };
    prepare_vp_imports(wasm_store, initial_memory, &env)
}

/// Prepare imports (memory and host functions) exposed to the vm guest running
/// validity predicate code
pub fn prepare_vp_imports<DB>(
    wasm_store: &Store,
    initial_memory: Memory,
    env: &VpEnv<'static, DB>,
) -> ImportObject
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
{
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            // Each function takes ownership of the environment (wrappers around references, cheap to clone), so we need to clone it
            "gas" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_charge_gas),
            "_read_pre" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_read_pre),
            "_read_post" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_read_post),
            "_has_key_pre" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_has_key_pre),
            "_has_key_post" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_has_key_post),
            "_iter_prefix" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_iter_prefix),
            "_iter_pre_next" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_iter_pre_next),
            "_iter_post_next" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_storage_iter_post_next),
            "_get_chain_id" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_get_chain_id),
            "_get_block_height" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_get_block_height),
            "_get_block_hash" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_get_block_hash),
            "_verify_tx_signature" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_verify_tx_signature),
            "_log_string" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_log_string),
            "_eval" => wasmer::Function::new_native_with_env(wasm_store, env.clone(), vp_eval),
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
        memory: AnomaMemory::default(),
        inject_mm_message,
        tx_code: tx_code.as_ref().to_vec(),
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "_send_match" => wasmer::Function::new_native_with_env(wasm_store,
                                                                  env.clone(),
                                                                   send_match),
            "_update_data" => wasmer::Function::new_native_with_env(wasm_store,
                                                                    env.clone(),
                                                                    update_data),
            "_remove_intents" => wasmer::Function::new_native_with_env(wasm_store,
                                                                       env.clone(),
                                                                       remove_intents),
            "_log_string" => wasmer::Function::new_native_with_env(wasm_store,
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
        memory: AnomaMemory::default(),
    };
    wasmer::imports! {
        // default namespace
        "env" => {
            "memory" => initial_memory,
            "_log_string" => wasmer::Function::new_native_with_env(wasm_store,
                                                                  env,
                                                                   filter_log_string),
        },
    }
}

/// Called from tx wasm to request to use the given gas amount
fn tx_charge_gas<DB>(env: &TxEnv<'_, DB>, used_gas: i32)
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    tx_add_gas(env, used_gas as _)
}

fn tx_add_gas<DB>(env: &TxEnv<DB>, used_gas: u64)
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let gas_meter: &mut BlockGasMeter = unsafe { &mut *(env.gas_meter.get()) };
    // if we run out of gas, we need to stop the execution
    if let Err(err) = gas_meter.add(used_gas) {
        tracing::warn!(
            "Stopping transaction execution because of gas error: {}",
            err
        );
        unreachable!()
    }
}

/// Called from VP wasm to request to use the given gas amount
fn vp_charge_gas<'a, DB>(env: &VpEnv<'a, DB>, used_gas: i32)
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    vp_add_gas(env, used_gas as _)
}

fn vp_add_gas<'a, DB>(env: &VpEnv<'a, DB>, used_gas: u64)
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let gas_meter: &mut VpGasMeter = unsafe { &mut *(env.gas_meter.get()) };
    if let Err(err) = gas_meter.add(used_gas) {
        tracing::warn!(
            "Stopping transaction execution because of gas error: {}",
            err
        );
        unreachable!()
    }
}

/// Storage `has_key` function exposed to the wasm VM Tx environment. It will
/// try to check the write log first and if no entry found then the storage.
fn tx_storage_has_key<DB>(env: &TxEnv<DB>, key_ptr: u64, key_len: u64) -> u64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    tx_add_gas(env, gas);

    tracing::debug!("tx_storage_has_key {}, key {}", key, key_ptr,);

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
            let storage: &Storage<DB> = unsafe { env.storage.get() };
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
fn tx_storage_read<DB>(
    env: &TxEnv<DB>,
    key_ptr: u64,
    key_len: u64,
    result_ptr: u64,
) -> i64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    tx_add_gas(env, gas);

    tracing::debug!(
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
            let storage: &Storage<DB> = unsafe { env.storage.get() };
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
/// ID of the iterator.
fn tx_storage_iter_prefix<DB>(
    env: &TxEnv<'static, DB>,
    prefix_ptr: u64,
    prefix_len: u64,
) -> u64
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (prefix, gas) = env
        .memory
        .read_string(prefix_ptr, prefix_len as _)
        .expect("Cannot read the prefix from memory");
    tx_add_gas(env, gas);

    tracing::debug!("tx_storage_iter_prefix {}, prefix {}", prefix, prefix_ptr);

    let prefix = Key::parse(prefix).expect("Cannot parse the prefix string");

    let storage: &Storage<DB> = unsafe { env.storage.get() };
    let iterators: &mut PrefixIterators<DB> =
        unsafe { &mut *(env.iterators.get()) };
    let (iter, gas) = storage.iter_prefix(&prefix);
    tx_add_gas(env, gas);
    iterators.insert(iter).id()
}

/// Storage prefix iterator next function exposed to the wasm VM Tx environment.
/// It will try to read from the write log first and if no entry found then from
/// the storage.
///
/// Returns [`-1`] when the key is not present, or the length of the data when
/// the key is present (the length may be [`0`]).
fn tx_storage_iter_next<DB>(
    env: &TxEnv<DB>,
    iter_id: u64,
    result_ptr: u64,
) -> i64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    tracing::debug!(
        "tx_storage_iter_next iter_id {}, result_ptr {}",
        iter_id,
        result_ptr,
    );

    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    let iterators: &mut PrefixIterators<DB> =
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
fn tx_storage_write<DB>(
    env: &TxEnv<DB>,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
) where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
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

    tracing::debug!("tx_storage_update {}, {:#?}", key, value);

    let key = Key::parse(key).expect("Cannot parse the key string");

    // check address existence
    let write_log: &WriteLog = unsafe { &*(env.write_log.get()) };
    let storage: &Storage<DB> = unsafe { env.storage.get() };
    for addr in key.find_addresses() {
        let vp_key = Key::validity_predicate(&addr)
            .expect("Unable to create a validity predicate key");
        let (vp, gas) = write_log.read(&vp_key);
        tx_add_gas(env, gas);
        // just check the existence because the write log should not have the
        // delete log of the VP
        if vp.is_none() {
            let (is_present, gas) =
                storage.has_key(&vp_key).expect("checking existence failed");
            tx_add_gas(env, gas);
            if !is_present {
                tracing::info!(
                    "Trying to write into storage with a key containing an \
                     address that doesn't exist: {}",
                    addr
                );
                unreachable!();
            }
        }
    }

    let write_log: &mut WriteLog = unsafe { &mut *(env.write_log.get()) };
    let (gas, _size_diff) = write_log.write(&key, value);
    tx_add_gas(env, gas);
    // TODO: charge the size diff
}

/// Storage delete function exposed to the wasm VM Tx environment. The given
/// key/value will be written as deleted to the write log.
fn tx_storage_delete<DB>(env: &TxEnv<DB>, key_ptr: u64, key_len: u64) -> u64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    tx_add_gas(env, gas);

    tracing::debug!("tx_storage_delete {}", key);

    let key = Key::parse(key).expect("Cannot parse the key string");

    let write_log: &mut WriteLog = unsafe { &mut *(env.write_log.get()) };
    let (gas, _size_diff) = write_log.delete(&key);
    tx_add_gas(env, gas);
    // TODO: charge the size diff

    1
}

/// Storage read prior state (before tx execution) function exposed to the wasm
/// VM VP environment. It will try to read from the storage.
///
/// Returns [`-1`] when the key is not present, or the length of the data when
/// the key is present (the length may be [`0`]).
fn vp_storage_read_pre<'a, DB>(
    env: &VpEnv<'a, DB>,
    key_ptr: u64,
    key_len: u64,
    result_ptr: u64,
) -> i64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    vp_add_gas(env, gas);

    // try to read from the storage
    let key = Key::parse(key).expect("Cannot parse the key string");
    let storage: &Storage<DB> = unsafe { env.storage.get() };
    let (value, gas) = storage.read(&key).expect("storage read failed");
    vp_add_gas(env, gas);
    tracing::debug!(
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
fn vp_storage_read_post<'a, DB>(
    env: &VpEnv<'a, DB>,
    key_ptr: u64,
    key_len: u64,
    result_ptr: u64,
) -> i64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    vp_add_gas(env, gas);

    tracing::debug!(
        "vp_storage_read_post {}, key {}, result_ptr {}",
        key,
        key_ptr,
        result_ptr,
    );

    // try to read from the write log first
    let key = Key::parse(key).expect("Cannot parse the key string");
    let write_log: &WriteLog = unsafe { env.write_log.get() };
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
            let storage: &Storage<DB> = unsafe { env.storage.get() };
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
fn vp_storage_has_key_pre<'a, DB>(
    env: &VpEnv<'a, DB>,
    key_ptr: u64,
    key_len: u64,
) -> u64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    vp_add_gas(env, gas);

    tracing::debug!("vp_storage_has_key_pre {}, key {}", key, key_ptr,);

    let key = Key::parse(key).expect("Cannot parse the key string");

    let storage: &Storage<DB> = unsafe { env.storage.get() };
    let (present, gas) = storage.has_key(&key).expect("storage has_key failed");
    vp_add_gas(env, gas);
    if present { 1 } else { 0 }
}

/// Storage `has_key` in posterior state (after tx execution) function exposed
/// to the wasm VM VP environment. It will
/// try to check the write log first and if no entry found then the storage.
fn vp_storage_has_key_post<'a, DB>(
    env: &VpEnv<'a, DB>,
    key_ptr: u64,
    key_len: u64,
) -> u64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .expect("Cannot read the key from memory");
    vp_add_gas(env, gas);

    tracing::debug!("vp_storage_has_key_post {}, key {}", key, key_ptr,);

    let key = Key::parse(key).expect("Cannot parse the key string");

    // try to read from the write log first
    let write_log: &WriteLog = unsafe { env.write_log.get() };
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
            let storage: &Storage<DB> = unsafe { env.storage.get() };
            let (present, gas) =
                storage.has_key(&key).expect("storage has_key failed");
            vp_add_gas(env, gas);
            if present { 1 } else { 0 }
        }
    }
}

/// Storage prefix iterator function exposed to the wasm VM VP environment.
/// It will try to get an iterator from the storage and return the corresponding
/// ID of the iterator.
fn vp_storage_iter_prefix<DB>(
    env: &VpEnv<'static, DB>,
    prefix_ptr: u64,
    prefix_len: u64,
) -> u64
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (prefix, gas) = env
        .memory
        .read_string(prefix_ptr, prefix_len as _)
        .expect("Cannot read the prefix from memory");
    vp_add_gas(env, gas);

    tracing::debug!("vp_storage_iter_prefix {}, prefix {}", prefix, prefix_ptr);

    let prefix = Key::parse(prefix).expect("Cannot parse the prefix string");

    let storage: &Storage<DB> = unsafe { env.storage.get() };
    let iterators: &mut PrefixIterators<DB> =
        unsafe { &mut *(env.iterators.get()) };
    let (iter, gas) = (*storage).iter_prefix(&prefix);
    vp_add_gas(env, gas);
    iterators.insert(iter).id()
}

/// Storage prefix iterator for prior state (before tx execution) function
/// exposed to the wasm VM VP environment. It will try to read from the storage.
///
/// Returns [`-1`] when the key is not present, or the length of the data when
/// the key is present (the length may be [`0`]).
fn vp_storage_iter_pre_next<'a, DB>(
    env: &VpEnv<'a, DB>,
    iter_id: u64,
    result_ptr: u64,
) -> i64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    tracing::debug!(
        "vp_storage_iter_pre_next iter_id {}, result_ptr {}",
        iter_id,
        result_ptr,
    );

    let iterators: &mut PrefixIterators<DB> =
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
fn vp_storage_iter_post_next<'a, DB>(
    env: &VpEnv<'a, DB>,
    iter_id: u64,
    result_ptr: u64,
) -> i64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    tracing::debug!(
        "vp_storage_iter_post_next iter_id {}, result_ptr {}",
        iter_id,
        result_ptr,
    );

    let write_log: &WriteLog = unsafe { env.write_log.get() };
    let iterators: &mut PrefixIterators<DB> =
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
fn tx_insert_verifier<DB>(env: &TxEnv<DB>, addr_ptr: u64, addr_len: u64)
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (addr, gas) = env
        .memory
        .read_string(addr_ptr, addr_len as _)
        .expect("Cannot read the key from memory");
    tx_add_gas(env, gas);

    tracing::debug!("tx_insert_verifier {}, addr_ptr {}", addr, addr_ptr,);

    let addr = Address::decode(&addr).expect("Cannot parse the address string");

    let verifiers: &mut HashSet<Address> =
        unsafe { &mut *(env.verifiers.get()) };
    verifiers.insert(addr);
    tx_add_gas(env, addr_len);
}

/// Update a validity predicate function exposed to the wasm VM Tx environment
fn tx_update_validity_predicate<DB>(
    env: &TxEnv<DB>,
    addr_ptr: u64,
    addr_len: u64,
    code_ptr: u64,
    code_len: u64,
) where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (addr, gas) = env
        .memory
        .read_string(addr_ptr, addr_len as _)
        .expect("Cannot read the address from memory");
    tx_add_gas(env, gas);

    let addr = Address::decode(addr).expect("Failed to decode the address");
    tracing::debug!("tx_update_validity_predicate for addr {}", addr);

    let key =
        Key::validity_predicate(&addr).expect("Cannot make the key for the VP");
    let (code, gas) = env
        .memory
        .read_bytes(code_ptr, code_len as _)
        .expect("Cannot read the VP code");
    tx_add_gas(env, gas);

    tx_add_gas(env, code.len() as u64 * WASM_VALIDATION_GAS_PER_BYTE);
    if let Err(err) = super::validate_untrusted_wasm(&code) {
        tracing::info!(
            "Trying to update an account with an invalid validity predicate \
             code, error: {:#?}",
            err
        );
        unreachable!()
    }

    let write_log: &mut WriteLog = unsafe { &mut *(env.write_log.get()) };
    let (gas, _size_diff) = write_log.write(&key, code);
    tx_add_gas(env, gas);
    // TODO: charge the size diff
}

/// Initialize a new account established address.
fn tx_init_account<DB>(
    env: &TxEnv<DB>,
    code_ptr: u64,
    code_len: u64,
    result_ptr: u64,
) -> u64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (code, gas) = env
        .memory
        .read_bytes(code_ptr, code_len as _)
        .expect("Cannot read validity predicate from memory");
    tx_add_gas(env, gas);

    tx_add_gas(env, code.len() as u64 * WASM_VALIDATION_GAS_PER_BYTE);
    if let Err(err) = super::validate_untrusted_wasm(&code) {
        tracing::info!(
            "Trying to initialize an account with an invalid validity \
             predicate code, error: {:#?}",
            err
        );
        unreachable!()
    }

    tracing::debug!("tx_init_account");

    let storage: &Storage<DB> = unsafe { env.storage.get() };
    let write_log: &mut WriteLog = unsafe { &mut *(env.write_log.get()) };
    let (addr, gas) = write_log.init_account(&storage.address_gen, code);
    let addr_bytes =
        addr.try_to_vec().expect("Encoding address shouldn't fail");
    let result_len = addr_bytes.len() as u64;
    tx_add_gas(env, gas);
    let gas = env
        .memory
        .write_bytes(result_ptr, addr_bytes)
        .expect("cannot write to memory");
    tx_add_gas(env, gas);
    result_len
}

/// Getting the chain ID function exposed to the wasm VM Tx environment.
fn tx_get_chain_id<DB>(env: &TxEnv<DB>, result_ptr: u64)
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let storage: &Storage<DB> = unsafe { env.storage.get() };
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
fn tx_get_block_height<DB>(env: &TxEnv<DB>) -> u64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let storage: &Storage<DB> = unsafe { env.storage.get() };
    let (height, gas) = storage.get_block_height();
    tx_add_gas(env, gas);
    height.0
}

/// Getting the block hash function exposed to the wasm VM Tx environment. The
/// hash is that of the block to which the current transaction is being applied.
fn tx_get_block_hash<DB>(env: &TxEnv<DB>, result_ptr: u64)
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let storage: &Storage<DB> = unsafe { env.storage.get() };
    let (hash, gas) = storage.get_block_hash();
    tx_add_gas(env, gas);
    let gas = env
        .memory
        .write_bytes(result_ptr, hash.0)
        .expect("cannot write to memory");
    tx_add_gas(env, gas);
}

/// Getting the chain ID function exposed to the wasm VM VP environment.
fn vp_get_chain_id<'a, DB>(env: &VpEnv<'a, DB>, result_ptr: u64)
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let storage: &Storage<DB> = unsafe { env.storage.get() };
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
fn vp_get_block_height<'a, DB>(env: &VpEnv<'a, DB>) -> u64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let storage: &Storage<DB> = unsafe { env.storage.get() };
    let (height, gas) = storage.get_block_height();
    vp_add_gas(env, gas);
    height.0
}

/// Getting the block hash function exposed to the wasm VM VP environment. The
/// hash is that of the block to which the current transaction is being applied.
fn vp_get_block_hash<'a, DB>(env: &VpEnv<'a, DB>, result_ptr: u64)
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let storage: &Storage<DB> = unsafe { env.storage.get() };
    let (hash, gas) = storage.get_block_hash();
    vp_add_gas(env, gas);
    let gas = env
        .memory
        .write_bytes(result_ptr, hash.0)
        .expect("cannot write to memory");
    vp_add_gas(env, gas);
}

fn vp_verify_tx_signature<'a, DB>(
    env: &VpEnv<'a, DB>,
    pk_ptr: u64,
    pk_len: u64,
    data_ptr: u64,
    data_len: u64,
    sig_ptr: u64,
    sig_len: u64,
) -> u64
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
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

    let tx_code = unsafe { env.tx_code.get() };
    vp_add_gas(env, (data.len() + tx_code.len()) as _);
    let signature_data = [&data[..], tx_code].concat();

    vp_add_gas(env, VERIFY_TX_SIG_GAS_COST);
    if verify_signature_raw(&pk, &signature_data, &sig).is_ok() {
        1
    } else {
        0
    }
}

/// Log a string from exposed to the wasm VM Tx environment. The message will be
/// printed at the [`tracing::Level::Info`]. This function is for development
/// only.
fn tx_log_string<DB>(env: &TxEnv<DB>, str_ptr: u64, str_len: u64)
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (str, _gas) = env
        .memory
        .read_string(str_ptr, str_len as _)
        .expect("Cannot read the string from memory");

    tracing::info!("WASM Transaction log: {}", str);
}

/// Log a string from exposed to the wasm VM VP environment. The message will be
/// printed at the [`tracing::Level::Info`]. This function is for development
/// only.
fn vp_log_string<'a, DB>(env: &VpEnv<'a, DB>, str_ptr: u64, str_len: u64)
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    let (str, _gas) = env
        .memory
        .read_string(str_ptr, str_len as _)
        .expect("Cannot read the string from memory");

    tracing::info!("WASM Validity predicate log: {}", str);
}

fn vp_eval<DB>(
    env: &VpEnv<'static, DB>,
    vp_code_ptr: u64,
    vp_code_len: u64,
    input_data_ptr: u64,
    input_data_len: u64,
) -> u64
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>, /* Generic over a lifetime */
{
    let (vp_code, gas) = env
        .memory
        .read_bytes(vp_code_ptr, vp_code_len as _)
        .expect("Cannot read bytes from memory");
    vp_add_gas(env, gas);

    let (input_data, gas) = env
        .memory
        .read_bytes(input_data_ptr, input_data_len as _)
        .expect("Cannot read bytes from memory");
    vp_add_gas(env, gas);

    let vp_runner = VpRunner::new();
    // Clone everything except for the memory
    let new_env = VpEnv {
        addr: env.addr.clone(),
        iterators: env.iterators.clone(),
        storage: env.storage.clone(),
        write_log: env.write_log.clone(),
        gas_meter: env.gas_meter.clone(),
        tx_code: env.tx_code.clone(),
        keys_changed: env.keys_changed.clone(),
        verifiers: env.verifiers.clone(),
        memory: AnomaMemory::default(),
    };

    let result = vp_runner.run_eval(vp_code, &input_data, new_env);

    match result {
        Ok(b) => {
            if b {
                1
            } else {
                0
            }
        }
        Err(_e) => 0,
    }
}

/// Log a string from exposed to the wasm VM matchmaker environment. The message
/// will be printed at the [`tracing::Level::Info`]. This function is for
/// development only.
fn matchmaker_log_string(env: &MatchmakerEnv, str_ptr: u64, str_len: u64) {
    let (str, _gas) = env
        .memory
        .read_string(str_ptr, str_len as _)
        .expect("Cannot read the string from memory");

    tracing::info!("WASM Matchmaker log: {}", str);
}

/// Log a string from exposed to the wasm VM filter environment. The message
/// will be printed at the [`tracing::Level::Info`].
fn filter_log_string(env: &FilterEnv, str_ptr: u64, str_len: u64) {
    let (str, _gas) = env
        .memory
        .read_string(str_ptr, str_len as _)
        .expect("Cannot read the string from memory");
    tracing::info!("WASM Filter log: {}", str);
}

fn remove_intents(
    env: &MatchmakerEnv,
    intents_id_ptr: u64,
    intents_id_len: u64,
) {
    let (intents_id_bytes, _gas) = env
        .memory
        .read_bytes(intents_id_ptr, intents_id_len as _)
        .expect("Cannot read the intents from memory");

    let intents_id =
        HashSet::<Vec<u8>>::try_from_slice(&intents_id_bytes).unwrap();

    env.inject_mm_message
        .try_send(MatchmakerMessage::RemoveIntents(intents_id))
        .expect("failed to send intents_id")
}

/// Inject a transaction from matchmaker's matched intents to the ledger
fn send_match(env: &MatchmakerEnv, data_ptr: u64, data_len: u64) {
    let (tx_data, _gas) = env
        .memory
        .read_bytes(data_ptr, data_len as _)
        .expect("Cannot read the key from memory");
    // TODO sign in the matchmaker module instead. use a ref for the tx_code
    // here to avoid copying
    let tx_code = env.tx_code.clone();
    let keypair = wallet::matchmaker_keypair();
    let signed = SignedTxData::new(&keypair, tx_data, &tx_code);
    let signed_bytes = signed
        .try_to_vec()
        .expect("Couldn't encoded signed matchmaker tx data");
    let tx = Tx {
        code: tx_code,
        data: Some(signed_bytes),
        timestamp: Some(std::time::SystemTime::now().into()),
    };
    env.inject_mm_message
        .try_send(MatchmakerMessage::InjectTx(tx))
        .expect("failed to send tx")
}

fn update_data(env: &MatchmakerEnv, data_ptr: u64, data_len: u64) {
    let (data, _gas) = env
        .memory
        .read_bytes(data_ptr, data_len as _)
        .expect("Cannot read the data from memory");

    env.inject_mm_message
        .try_send(MatchmakerMessage::UpdateData(data))
        .expect("failed to send updated data")
}
