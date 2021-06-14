//! Virtual machine's host environment exposes functions that may be called from
//! within a virtual machine.
use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::{Arc, Mutex};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::gossip::mm::MmHost;
use crate::ledger::gas::{BlockGasMeter, VpGasMeter};
use crate::ledger::storage::write_log::{self, WriteLog};
use crate::ledger::storage::{self, Storage, StorageHasher};
use crate::types::internal::HostEnvResult;
use crate::types::key::ed25519::{verify_signature_raw, PublicKey, Signature};
use crate::types::{Address, Key};
use crate::vm::memory::VmMemory;
use crate::vm::prefix_iter::{PrefixIteratorId, PrefixIterators};
use crate::vm::types::KeyVal;
use crate::vm::{EnvHostSliceWrapper, EnvHostWrapper, MutEnvHostWrapper};

const VERIFY_TX_SIG_GAS_COST: u64 = 1000;
const WASM_VALIDATION_GAS_PER_BYTE: u64 = 1;

/// A transaction's host environment
pub struct TxEnv<'a, MEM, DB, H>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    /// The VM memory for bi-directional data passing
    pub memory: MEM,
    /// Read-only access to the storage
    pub storage: EnvHostWrapper<'a, &'a Storage<DB, H>>,
    /// Read/write access to the write log.
    /// Not thread-safe, assuming single-threaded Tx runner
    pub write_log: MutEnvHostWrapper<'a, &'a WriteLog>,
    /// Storage prefix iterators.
    /// Not thread-safe, assuming single-threaded Tx runner
    pub iterators: MutEnvHostWrapper<'a, &'a PrefixIterators<'a, DB>>,
    /// Transaction gas meter.
    /// Not thread-safe, assuming single-threaded Tx runner
    pub gas_meter: MutEnvHostWrapper<'a, &'a BlockGasMeter>,
    /// The verifiers whose validity predicates should be triggered.
    /// Not thread-safe, assuming single-threaded Tx runner
    pub verifiers: MutEnvHostWrapper<'a, &'a HashSet<Address>>,
    /// Cache for 2-step reads from host environment.
    /// Not thread-safe, assuming single-threaded Tx runner
    pub result_buffer: MutEnvHostWrapper<'a, &'a Option<Vec<u8>>>,
}

impl<MEM, DB, H> Clone for TxEnv<'_, MEM, DB, H>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    fn clone(&self) -> Self {
        Self {
            memory: self.memory.clone(),
            storage: self.storage.clone(),
            write_log: self.write_log.clone(),
            iterators: self.iterators.clone(),
            gas_meter: self.gas_meter.clone(),
            verifiers: self.verifiers.clone(),
            result_buffer: self.result_buffer.clone(),
        }
    }
}

/// A validity predicate's host environment
pub struct VpEnv<'a, MEM, DB, H, EVAL>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    /// The VM memory for bi-directional data passing
    pub memory: MEM,
    /// The address of the account that owns the VP
    pub address: Address,
    /// Read-only access to the storage.
    /// Thread-safe read-only access from parallel Vp runners
    pub storage: EnvHostWrapper<'a, &'a Storage<DB, H>>,
    /// Read-only access to the write log.
    /// Thread-safe read-only access from parallel Vp runners
    pub write_log: EnvHostWrapper<'a, &'a WriteLog>,
    /// Storage prefix iterators.
    /// This is not thread-safe, but because each VP has its own instance there
    /// is no shared access
    pub iterators: MutEnvHostWrapper<'a, &'a PrefixIterators<'a, DB>>,
    /// VP gas meter.
    /// This is not thread-safe, but because each VP has its own instance there
    /// is no shared access
    pub gas_meter: MutEnvHostWrapper<'a, &'a VpGasMeter>,
    /// The transaction code is used for signature verification
    pub tx_code: EnvHostSliceWrapper<'a, &'a [u8]>,
    /// The runner of the [`vp_eval`] function
    pub eval_runner: EnvHostWrapper<'a, &'a EVAL>,
    /// Cache for 2-step reads from host environment.
    /// This is not thread-safe, but because each VP has its own instance there
    /// is no shared access
    pub result_buffer: MutEnvHostWrapper<'a, &'a Option<Vec<u8>>>,
}

/// A Validity predicate runner for calls from the [`vp_eval`] function.
pub trait VpEvalRunner {
    /// Evaluate a given validity predicate code with the given input data.
    fn eval(&self, vp_code: Vec<u8>, input_data: Vec<u8>) -> HostEnvResult;
}

impl<MEM, DB, H, EVAL> Clone for VpEnv<'_, MEM, DB, H, EVAL>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    fn clone(&self) -> Self {
        Self {
            memory: self.memory.clone(),
            address: self.address.clone(),
            storage: self.storage.clone(),
            write_log: self.write_log.clone(),
            iterators: self.iterators.clone(),
            gas_meter: self.gas_meter.clone(),
            tx_code: self.tx_code.clone(),
            eval_runner: self.eval_runner.clone(),
            result_buffer: self.result_buffer.clone(),
        }
    }
}

/// A matchmakers's host environment
pub struct MatchmakerEnv<MEM, MM>
where
    MEM: VmMemory,
    MM: MmHost,
{
    /// The VM memory for bi-directional data passing
    pub memory: MEM,
    /// The matchmaker's host
    pub mm: Arc<Mutex<MM>>,
}

impl<MEM, MM> Clone for MatchmakerEnv<MEM, MM>
where
    MEM: VmMemory,
    MM: MmHost,
{
    fn clone(&self) -> Self {
        Self {
            memory: self.memory.clone(),
            mm: self.mm.clone(),
        }
    }
}

unsafe impl<MEM, MM> Send for MatchmakerEnv<MEM, MM>
where
    MEM: VmMemory,
    MM: MmHost,
{
}

unsafe impl<MEM, MM> Sync for MatchmakerEnv<MEM, MM>
where
    MEM: VmMemory,
    MM: MmHost,
{
}

#[derive(Clone)]
/// A matchmakers filter's host environment
pub struct FilterEnv<MEM>
where
    MEM: VmMemory,
{
    /// The VM memory for bi-directional data passing
    pub memory: MEM,
}

/// Called from tx wasm to request to use the given gas amount
pub fn tx_charge_gas<MEM, DB, H>(env: &TxEnv<MEM, DB, H>, used_gas: i32)
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    tx_add_gas(env, used_gas as _)
}

/// Add a gas cost incured in a transaction
pub fn tx_add_gas<MEM, DB, H>(env: &TxEnv<MEM, DB, H>, used_gas: u64)
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
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
pub fn vp_charge_gas<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    used_gas: i32,
) where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    vp_add_gas(env, used_gas as _)
}

/// Add a gas cost incured in a validity predicate
pub fn vp_add_gas<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    used_gas: u64,
) where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
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
pub fn tx_has_key<MEM, DB, H>(
    env: &TxEnv<MEM, DB, H>,
    key_ptr: u64,
    key_len: u64,
) -> i64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (key, gas) = env.memory.read_string(key_ptr, key_len as _);
    tx_add_gas(env, gas);

    tracing::debug!("tx_has_key {}, key {}", key, key_ptr,);

    let key = Key::parse(key).expect("Cannot parse the key string");

    // try to read from the write log first
    let write_log = unsafe { env.write_log.get() };
    let (log_val, gas) = write_log.read(&key);
    tx_add_gas(env, gas);
    match log_val {
        Some(&write_log::StorageModification::Write { .. }) => {
            HostEnvResult::Success.to_i64()
        }
        Some(&write_log::StorageModification::Delete) => {
            // the given key has been deleted
            HostEnvResult::Fail.to_i64()
        }
        Some(&write_log::StorageModification::InitAccount { .. }) => {
            HostEnvResult::Success.to_i64()
        }
        None => {
            // when not found in write log, try to check the storage
            let storage = unsafe { env.storage.get() };
            let (present, gas) =
                storage.has_key(&key).expect("storage has_key failed");
            tx_add_gas(env, gas);
            HostEnvResult::from(present).to_i64()
        }
    }
}

/// Storage read function exposed to the wasm VM Tx environment. It will try to
/// read from the write log first and if no entry found then from the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn tx_read<MEM, DB, H>(
    env: &TxEnv<MEM, DB, H>,
    key_ptr: u64,
    key_len: u64,
) -> i64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (key, gas) = env.memory.read_string(key_ptr, key_len as _);
    tx_add_gas(env, gas);

    tracing::debug!("tx_read {}, key {}", key, key_ptr,);

    let key = Key::parse(key).expect("Cannot parse the key string");

    // try to read from the write log first
    let write_log = unsafe { env.write_log.get() };
    let (log_val, gas) = write_log.read(&key);
    tx_add_gas(env, gas);
    match log_val {
        Some(&write_log::StorageModification::Write { ref value }) => {
            let len: i64 =
                value.len().try_into().expect("data length overflow");
            let result_buffer = unsafe { env.result_buffer.get() };
            result_buffer.replace(value.clone());
            len
        }
        Some(&write_log::StorageModification::Delete) => {
            // fail, given key has been deleted
            HostEnvResult::Fail.to_i64()
        }
        Some(&write_log::StorageModification::InitAccount {
            ref vp, ..
        }) => {
            // read the VP of a new account
            let len: i64 = vp.len() as _;
            let result_buffer = unsafe { env.result_buffer.get() };
            result_buffer.replace(vp.clone());
            len
        }
        None => {
            // when not found in write log, try to read from the storage
            let storage = unsafe { env.storage.get() };
            let (value, gas) = storage.read(&key).expect("storage read failed");
            tx_add_gas(env, gas);
            match value {
                Some(value) => {
                    let len: i64 =
                        value.len().try_into().expect("data length overflow");
                    let result_buffer = unsafe { env.result_buffer.get() };
                    result_buffer.replace(value);
                    len
                }
                None => HostEnvResult::Fail.to_i64(),
            }
        }
    }
}

/// This function is a helper to handle the first step of reading var-len
/// values from the host.
///
/// In cases where we're reading a value from the host in the guest and
/// we don't know the byte size up-front, we have to read it in 2-steps. The
/// first step reads the value into a result buffer and returns the size (if
/// any) back to the guest, the second step reads the value from cache into a
/// pre-allocated buffer with the obtained size.
pub fn tx_result_buffer<MEM, DB, H>(env: &TxEnv<MEM, DB, H>, result_ptr: u64)
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let result_buffer = unsafe { env.result_buffer.get() };
    let value = result_buffer.take().unwrap();
    let gas = env.memory.write_bytes(result_ptr, value);
    tx_add_gas(env, gas);
}

/// Storage prefix iterator function exposed to the wasm VM Tx environment.
/// It will try to get an iterator from the storage and return the corresponding
/// ID of the iterator.
pub fn tx_iter_prefix<MEM, DB, H>(
    env: &TxEnv<MEM, DB, H>,
    prefix_ptr: u64,
    prefix_len: u64,
) -> u64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (prefix, gas) = env.memory.read_string(prefix_ptr, prefix_len as _);
    tx_add_gas(env, gas);

    tracing::debug!("tx_iter_prefix {}, prefix {}", prefix, prefix_ptr);

    let prefix = Key::parse(prefix).expect("Cannot parse the prefix string");

    let storage = unsafe { env.storage.get() };
    let iterators = unsafe { env.iterators.get() };
    let (iter, gas) = storage.iter_prefix(&prefix);
    tx_add_gas(env, gas);
    iterators.insert(iter).id()
}

/// Storage prefix iterator next function exposed to the wasm VM Tx environment.
/// It will try to read from the write log first and if no entry found then from
/// the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn tx_iter_next<MEM, DB, H>(env: &TxEnv<MEM, DB, H>, iter_id: u64) -> i64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    tracing::debug!("tx_iter_next iter_id {}", iter_id,);

    let write_log = unsafe { env.write_log.get() };
    let iterators = unsafe { env.iterators.get() };
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
                let result_buffer = unsafe { env.result_buffer.get() };
                result_buffer.replace(key_val);
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
                let result_buffer = unsafe { env.result_buffer.get() };
                result_buffer.replace(key_val);
                return len;
            }
        }
    }
    HostEnvResult::Fail.to_i64()
}

/// Storage write function exposed to the wasm VM Tx environment. The given
/// key/value will be written to the write log.
pub fn tx_write<MEM, DB, H>(
    env: &TxEnv<MEM, DB, H>,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
) where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (key, gas) = env.memory.read_string(key_ptr, key_len as _);
    tx_add_gas(env, gas);
    let (value, gas) = env.memory.read_bytes(val_ptr, val_len as _);
    tx_add_gas(env, gas);

    tracing::debug!("tx_update {}, {:?}", key, value);

    let key = Key::parse(key).expect("Cannot parse the key string");

    // check address existence
    let write_log = unsafe { env.write_log.get() };
    let storage = unsafe { env.storage.get() };
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

    let (gas, _size_diff) = write_log.write(&key, value);
    tx_add_gas(env, gas);
    // TODO: charge the size diff
}

/// Storage delete function exposed to the wasm VM Tx environment. The given
/// key/value will be written as deleted to the write log.
pub fn tx_delete<MEM, DB, H>(
    env: &TxEnv<MEM, DB, H>,
    key_ptr: u64,
    key_len: u64,
) where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (key, gas) = env.memory.read_string(key_ptr, key_len as _);
    tx_add_gas(env, gas);

    tracing::debug!("tx_delete {}", key);

    let key = Key::parse(key).expect("Cannot parse the key string");

    let write_log = unsafe { env.write_log.get() };
    let (gas, _size_diff) = write_log.delete(&key);
    tx_add_gas(env, gas);
    // TODO: charge the size diff
}

/// Storage read prior state (before tx execution) function exposed to the wasm
/// VM VP environment. It will try to read from the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn vp_read_pre<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    key_ptr: u64,
    key_len: u64,
) -> i64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    let (key, gas) = env.memory.read_string(key_ptr, key_len as _);
    vp_add_gas(env, gas);

    // try to read from the storage
    let key = Key::parse(key).expect("Cannot parse the key string");
    let storage = unsafe { env.storage.get() };
    let (value, gas) = storage.read(&key).expect("storage read failed");
    vp_add_gas(env, gas);
    tracing::debug!(
        "vp_read_pre addr {}, key {}, value {:?}",
        env.address,
        key,
        value,
    );
    match value {
        Some(value) => {
            let len: i64 =
                value.len().try_into().expect("data length overflow");
            let result_buffer = unsafe { env.result_buffer.get() };
            result_buffer.replace(value);
            len
        }
        None => HostEnvResult::Fail.to_i64(),
    }
}

/// Storage read posterior state (after tx execution) function exposed to the
/// wasm VM VP environment. It will try to read from the write log first and if
/// no entry found then from the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn vp_read_post<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    key_ptr: u64,
    key_len: u64,
) -> i64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    let (key, gas) = env.memory.read_string(key_ptr, key_len as _);
    vp_add_gas(env, gas);

    tracing::debug!("vp_read_post {}, key {}", key, key_ptr,);

    // try to read from the write log first
    let key = Key::parse(key).expect("Cannot parse the key string");
    let write_log = unsafe { env.write_log.get() };
    let (log_val, gas) = write_log.read(&key);
    vp_add_gas(env, gas);
    match log_val {
        Some(&write_log::StorageModification::Write { ref value }) => {
            let len: i64 =
                value.len().try_into().expect("data length overflow");
            let result_buffer = unsafe { env.result_buffer.get() };
            result_buffer.replace(value.clone());
            len
        }
        Some(&write_log::StorageModification::Delete) => {
            // fail, given key has been deleted
            HostEnvResult::Fail.to_i64()
        }
        Some(&write_log::StorageModification::InitAccount {
            ref vp, ..
        }) => {
            // read the VP of a new account
            let len: i64 = vp.len() as _;
            let result_buffer = unsafe { env.result_buffer.get() };
            result_buffer.replace(vp.clone());
            len
        }
        None => {
            // when not found in write log, try to read from the storage
            let storage = unsafe { env.storage.get() };
            let (value, gas) = storage.read(&key).expect("storage read failed");
            vp_add_gas(env, gas);
            match value {
                Some(value) => {
                    let len: i64 =
                        value.len().try_into().expect("data length overflow");
                    let result_buffer = unsafe { env.result_buffer.get() };
                    result_buffer.replace(value);
                    len
                }
                None => HostEnvResult::Fail.to_i64(),
            }
        }
    }
}

/// This function is a helper to handle the first step of reading var-len
/// values from the host.
///
/// In cases where we're reading a value from the host in the guest and
/// we don't know the byte size up-front, we have to read it in 2-steps. The
/// first step reads the value into a result buffer and returns the size (if
/// any) back to the guest, the second step reads the value from cache into a
/// pre-allocated buffer with the obtained size.
pub fn vp_result_buffer<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    result_ptr: u64,
) where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    let result_buffer = unsafe { env.result_buffer.get() };
    let value = result_buffer.take().unwrap();
    let gas = env.memory.write_bytes(result_ptr, value);
    vp_add_gas(env, gas);
}

/// Storage `has_key` in prior state (before tx execution) function exposed to
/// the wasm VM VP environment. It will try to read from the storage.
pub fn vp_has_key_pre<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    key_ptr: u64,
    key_len: u64,
) -> i64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    let (key, gas) = env.memory.read_string(key_ptr, key_len as _);
    vp_add_gas(env, gas);

    tracing::debug!("vp_has_key_pre {}, key {}", key, key_ptr,);

    let key = Key::parse(key).expect("Cannot parse the key string");

    let storage = unsafe { env.storage.get() };
    let (present, gas) = storage.has_key(&key).expect("storage has_key failed");
    vp_add_gas(env, gas);
    HostEnvResult::from(present).to_i64()
}

/// Storage `has_key` in posterior state (after tx execution) function exposed
/// to the wasm VM VP environment. It will
/// try to check the write log first and if no entry found then the storage.
pub fn vp_has_key_post<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    key_ptr: u64,
    key_len: u64,
) -> i64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    let (key, gas) = env.memory.read_string(key_ptr, key_len as _);
    vp_add_gas(env, gas);

    tracing::debug!("vp_has_key_post {}, key {}", key, key_ptr,);

    let key = Key::parse(key).expect("Cannot parse the key string");

    // try to read from the write log first
    let write_log = unsafe { env.write_log.get() };
    let (log_val, gas) = write_log.read(&key);
    vp_add_gas(env, gas);
    match log_val {
        Some(&write_log::StorageModification::Write { .. }) => {
            HostEnvResult::Success.to_i64()
        }
        Some(&write_log::StorageModification::Delete) => {
            // the given key has been deleted
            HostEnvResult::Fail.to_i64()
        }
        Some(&write_log::StorageModification::InitAccount { .. }) => {
            HostEnvResult::Success.to_i64()
        }
        None => {
            // when not found in write log, try to check the storage
            let storage = unsafe { env.storage.get() };
            let (present, gas) =
                storage.has_key(&key).expect("storage has_key failed");
            vp_add_gas(env, gas);
            HostEnvResult::from(present).to_i64()
        }
    }
}

/// Storage prefix iterator function exposed to the wasm VM VP environment.
/// It will try to get an iterator from the storage and return the corresponding
/// ID of the iterator.
pub fn vp_iter_prefix<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    prefix_ptr: u64,
    prefix_len: u64,
) -> u64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    let (prefix, gas) = env.memory.read_string(prefix_ptr, prefix_len as _);
    vp_add_gas(env, gas);

    tracing::debug!("vp_iter_prefix {}, prefix {}", prefix, prefix_ptr);

    let prefix = Key::parse(prefix).expect("Cannot parse the prefix string");

    let storage = unsafe { env.storage.get() };
    let iterators = unsafe { env.iterators.get() };
    let (iter, gas) = (*storage).iter_prefix(&prefix);
    vp_add_gas(env, gas);
    iterators.insert(iter).id()
}

/// Storage prefix iterator for prior state (before tx execution) function
/// exposed to the wasm VM VP environment. It will try to read from the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn vp_iter_pre_next<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    iter_id: u64,
) -> i64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    tracing::debug!("vp_iter_pre_next iter_id {}", iter_id,);

    let iterators = unsafe { env.iterators.get() };
    let iter_id = PrefixIteratorId::new(iter_id);
    if let Some((key, val, gas)) = iterators.next(iter_id) {
        vp_add_gas(env, gas);
        let key_val = KeyVal { key, val }
            .try_to_vec()
            .expect("cannot serialize the key value pair");
        let len: i64 = key_val.len().try_into().expect("data length overflow");
        let result_buffer = unsafe { env.result_buffer.get() };
        result_buffer.replace(key_val);
        return len;
    }
    HostEnvResult::Fail.to_i64()
}

/// Storage prefix iterator next for posterior state (after tx execution)
/// function exposed to the wasm VM VP environment. It will try to read from the
/// write log first and if no entry found then from the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn vp_iter_post_next<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    iter_id: u64,
) -> i64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    tracing::debug!("vp_iter_post_next iter_id {}", iter_id,);

    let write_log = unsafe { env.write_log.get() };
    let iterators = unsafe { env.iterators.get() };
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
                let result_buffer = unsafe { env.result_buffer.get() };
                result_buffer.replace(key_val);
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
                let result_buffer = unsafe { env.result_buffer.get() };
                result_buffer.replace(key_val);
                return len;
            }
        }
    }
    HostEnvResult::Fail.to_i64()
}

/// Verifier insertion function exposed to the wasm VM Tx environment.
pub fn tx_insert_verifier<MEM, DB, H>(
    env: &TxEnv<MEM, DB, H>,
    addr_ptr: u64,
    addr_len: u64,
) where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (addr, gas) = env.memory.read_string(addr_ptr, addr_len as _);
    tx_add_gas(env, gas);

    tracing::debug!("tx_insert_verifier {}, addr_ptr {}", addr, addr_ptr,);

    let addr = Address::decode(&addr).expect("Cannot parse the address string");

    let verifiers = unsafe { env.verifiers.get() };
    verifiers.insert(addr);
    tx_add_gas(env, addr_len);
}

/// Update a validity predicate function exposed to the wasm VM Tx environment
pub fn tx_update_validity_predicate<MEM, DB, H>(
    env: &TxEnv<MEM, DB, H>,
    addr_ptr: u64,
    addr_len: u64,
    code_ptr: u64,
    code_len: u64,
) where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (addr, gas) = env.memory.read_string(addr_ptr, addr_len as _);
    tx_add_gas(env, gas);

    let addr = Address::decode(addr).expect("Failed to decode the address");
    tracing::debug!("tx_update_validity_predicate for addr {}", addr);

    let key =
        Key::validity_predicate(&addr).expect("Cannot make the key for the VP");
    let (code, gas) = env.memory.read_bytes(code_ptr, code_len as _);
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

    let write_log = unsafe { env.write_log.get() };
    let (gas, _size_diff) = write_log.write(&key, code);
    tx_add_gas(env, gas);
    // TODO: charge the size diff
}

/// Initialize a new account established address.
pub fn tx_init_account<MEM, DB, H>(
    env: &TxEnv<MEM, DB, H>,
    code_ptr: u64,
    code_len: u64,
    result_ptr: u64,
) where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (code, gas) = env.memory.read_bytes(code_ptr, code_len as _);
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

    let storage = unsafe { env.storage.get() };
    let write_log = unsafe { env.write_log.get() };
    let (addr, gas) = write_log.init_account(&storage.address_gen, code);
    let addr_bytes =
        addr.try_to_vec().expect("Encoding address shouldn't fail");
    tx_add_gas(env, gas);
    let gas = env.memory.write_bytes(result_ptr, addr_bytes);
    tx_add_gas(env, gas);
}

/// Getting the chain ID function exposed to the wasm VM Tx environment.
pub fn tx_get_chain_id<MEM, DB, H>(env: &TxEnv<MEM, DB, H>, result_ptr: u64)
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let storage = unsafe { env.storage.get() };
    let (chain_id, gas) = storage.get_chain_id();
    tx_add_gas(env, gas);
    let gas = env.memory.write_string(result_ptr, chain_id);
    tx_add_gas(env, gas);
}

/// Getting the block height function exposed to the wasm VM Tx
/// environment. The height is that of the block to which the current
/// transaction is being applied.
pub fn tx_get_block_height<MEM, DB, H>(env: &TxEnv<MEM, DB, H>) -> u64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let storage = unsafe { env.storage.get() };
    let (height, gas) = storage.get_block_height();
    tx_add_gas(env, gas);
    height.0
}

/// Getting the block hash function exposed to the wasm VM Tx environment. The
/// hash is that of the block to which the current transaction is being applied.
pub fn tx_get_block_hash<MEM, DB, H>(env: &TxEnv<MEM, DB, H>, result_ptr: u64)
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let storage = unsafe { env.storage.get() };
    let (hash, gas) = storage.get_block_hash();
    tx_add_gas(env, gas);
    let gas = env.memory.write_bytes(result_ptr, hash.0);
    tx_add_gas(env, gas);
}

/// Getting the chain ID function exposed to the wasm VM VP environment.
pub fn vp_get_chain_id<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    result_ptr: u64,
) where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    let storage = unsafe { env.storage.get() };
    let (chain_id, gas) = storage.get_chain_id();
    vp_add_gas(env, gas);
    let gas = env.memory.write_string(result_ptr, chain_id);
    vp_add_gas(env, gas);
}

/// Getting the block height function exposed to the wasm VM VP
/// environment. The height is that of the block to which the current
/// transaction is being applied.
pub fn vp_get_block_height<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
) -> u64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    let storage = unsafe { env.storage.get() };
    let (height, gas) = storage.get_block_height();
    vp_add_gas(env, gas);
    height.0
}

/// Getting the block hash function exposed to the wasm VM VP environment. The
/// hash is that of the block to which the current transaction is being applied.
pub fn vp_get_block_hash<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    result_ptr: u64,
) where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    let storage = unsafe { env.storage.get() };
    let (hash, gas) = storage.get_block_hash();
    vp_add_gas(env, gas);
    let gas = env.memory.write_bytes(result_ptr, hash.0);
    vp_add_gas(env, gas);
}

/// Verify a transaction signature.
pub fn vp_verify_tx_signature<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    pk_ptr: u64,
    pk_len: u64,
    data_ptr: u64,
    data_len: u64,
    sig_ptr: u64,
    sig_len: u64,
) -> i64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    let (pk, gas) = env.memory.read_bytes(pk_ptr, pk_len as _);
    vp_add_gas(env, gas);
    let pk: PublicKey =
        BorshDeserialize::try_from_slice(&pk).expect("Canot decode public key");

    let (data, gas) = env.memory.read_bytes(data_ptr, data_len as _);
    vp_add_gas(env, gas);

    let (sig, gas) = env.memory.read_bytes(sig_ptr, sig_len as _);
    vp_add_gas(env, gas);
    let sig: Signature =
        BorshDeserialize::try_from_slice(&sig).expect("Canot decode signature");

    let tx_code = unsafe { env.tx_code.get() };
    vp_add_gas(env, (data.len() + tx_code.len()) as _);
    let signature_data = [&data[..], tx_code].concat();

    vp_add_gas(env, VERIFY_TX_SIG_GAS_COST);
    HostEnvResult::from(
        verify_signature_raw(&pk, &signature_data, &sig).is_ok(),
    )
    .to_i64()
}

/// Log a string from exposed to the wasm VM Tx environment. The message will be
/// printed at the [`tracing::Level::INFO`]. This function is for development
/// only.
pub fn tx_log_string<MEM, DB, H>(
    env: &TxEnv<MEM, DB, H>,
    str_ptr: u64,
    str_len: u64,
) where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (str, _gas) = env.memory.read_string(str_ptr, str_len as _);

    tracing::info!("WASM Transaction log: {}", str);
}

/// Evaluate a validity predicate with the given input data.
pub fn vp_eval<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    vp_code_ptr: u64,
    vp_code_len: u64,
    input_data_ptr: u64,
    input_data_len: u64,
) -> i64
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    let (vp_code, gas) = env.memory.read_bytes(vp_code_ptr, vp_code_len as _);
    vp_add_gas(env, gas);

    let (input_data, gas) =
        env.memory.read_bytes(input_data_ptr, input_data_len as _);
    vp_add_gas(env, gas);

    let eval_runner = unsafe { env.eval_runner.get() };
    eval_runner.eval(vp_code, input_data).to_i64()
}

/// Log a string from exposed to the wasm VM VP environment. The message will be
/// printed at the [`tracing::Level::INFO`]. This function is for development
/// only.
pub fn vp_log_string<MEM, DB, H, EVAL>(
    env: &VpEnv<MEM, DB, H, EVAL>,
    str_ptr: u64,
    str_len: u64,
) where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvalRunner,
{
    let (str, _gas) = env.memory.read_string(str_ptr, str_len as _);

    tracing::info!("WASM Validity predicate log: {}", str);
}

/// Remove given intents from the matchmaker's mempool
pub fn mm_remove_intents<MEM, MM>(
    env: &MatchmakerEnv<MEM, MM>,
    intents_id_ptr: u64,
    intents_id_len: u64,
) where
    MEM: VmMemory,
    MM: MmHost,
{
    let (intents_id_bytes, _gas) =
        env.memory.read_bytes(intents_id_ptr, intents_id_len as _);

    let intents_id =
        HashSet::<Vec<u8>>::try_from_slice(&intents_id_bytes).unwrap();

    let mm = env.mm.lock().unwrap();
    mm.remove_intents(intents_id);
}

/// Inject a transaction from matchmaker's matched intents to the ledger
pub fn mm_send_match<MEM, MM>(
    env: &MatchmakerEnv<MEM, MM>,
    data_ptr: u64,
    data_len: u64,
) where
    MEM: VmMemory,
    MM: MmHost,
{
    let (tx_data, _gas) = env.memory.read_bytes(data_ptr, data_len as _);

    let mm = env.mm.lock().unwrap();
    mm.inject_tx(tx_data);
}

/// Update matchmaker's state data
pub fn mm_update_data<MEM, MM>(
    env: &MatchmakerEnv<MEM, MM>,
    data_ptr: u64,
    data_len: u64,
) where
    MEM: VmMemory,
    MM: MmHost,
{
    let (data, _gas) = env.memory.read_bytes(data_ptr, data_len as _);

    let mm = env.mm.lock().unwrap();
    mm.update_data(data);
}

/// Log a string from exposed to the wasm VM matchmaker environment. The message
/// will be printed at the [`tracing::Level::INFO`]. This function is for
/// development only.
pub fn mm_log_string<MEM, MM>(
    env: &MatchmakerEnv<MEM, MM>,
    str_ptr: u64,
    str_len: u64,
) where
    MEM: VmMemory,
    MM: MmHost,
{
    let (str, _gas) = env.memory.read_string(str_ptr, str_len as _);

    tracing::info!("WASM Matchmaker log: {}", str);
}

/// Log a string from exposed to the wasm VM filter environment. The message
/// will be printed at the [`tracing::Level::INFO`].
pub fn mm_filter_log_string<MEM>(
    env: &FilterEnv<MEM>,
    str_ptr: u64,
    str_len: u64,
) where
    MEM: VmMemory,
{
    let (str, _gas) = env.memory.read_string(str_ptr, str_len as _);
    tracing::info!("WASM Filter log: {}", str);
}

/// A helper module for testing
#[cfg(feature = "testing")]
pub mod testing {
    use super::*;
    use crate::ledger::storage::{self, StorageHasher};
    use crate::vm::memory::testing::NativeMemory;

    /// Setup a transaction environment
    pub fn tx_env<DB, H>(
        storage: &Storage<DB, H>,
        write_log: &mut WriteLog,
        iterators: &mut PrefixIterators<'static, DB>,
        verifiers: &mut HashSet<Address>,
        gas_meter: &mut BlockGasMeter,
        result_buffer: &mut Option<Vec<u8>>,
    ) -> TxEnv<'static, NativeMemory, DB, H>
    where
        DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
        H: StorageHasher,
    {
        let storage = unsafe { EnvHostWrapper::new(storage) };
        let write_log = unsafe { MutEnvHostWrapper::new(write_log) };
        let iterators = unsafe { MutEnvHostWrapper::new(iterators) };
        let verifiers = unsafe { MutEnvHostWrapper::new(verifiers) };
        let gas_meter = unsafe { MutEnvHostWrapper::new(gas_meter) };
        let result_buffer = unsafe { MutEnvHostWrapper::new(result_buffer) };
        TxEnv {
            memory: NativeMemory,
            storage,
            write_log,
            iterators,
            verifiers,
            gas_meter,
            result_buffer,
        }
    }

    /// Setup a validity predicate environment
    #[allow(clippy::too_many_arguments)]
    pub fn vp_env<DB, H, EVAL>(
        address: Address,
        storage: &Storage<DB, H>,
        write_log: &WriteLog,
        iterators: &mut PrefixIterators<'static, DB>,
        gas_meter: &mut VpGasMeter,
        tx_code: &[u8],
        eval_runner: &EVAL,
        result_buffer: &mut Option<Vec<u8>>,
    ) -> VpEnv<'static, NativeMemory, DB, H, EVAL>
    where
        DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
        H: StorageHasher,
        EVAL: VpEvalRunner,
    {
        let storage = unsafe { EnvHostWrapper::new(storage) };
        let write_log = unsafe { EnvHostWrapper::new(write_log) };
        let iterators = unsafe { MutEnvHostWrapper::new(iterators) };
        let gas_meter = unsafe { MutEnvHostWrapper::new(gas_meter) };
        let tx_code = unsafe { EnvHostSliceWrapper::new(tx_code) };
        let eval_runner = unsafe { EnvHostWrapper::new(eval_runner) };
        let result_buffer = unsafe { MutEnvHostWrapper::new(result_buffer) };
        VpEnv {
            memory: NativeMemory,
            address,
            storage,
            write_log,
            iterators,
            gas_meter,
            tx_code,
            eval_runner,
            result_buffer,
        }
    }
}
