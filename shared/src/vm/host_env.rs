//! Virtual machine's host environment exposes functions that may be called from
//! within a virtual machine.
use std::collections::BTreeSet;
use std::convert::TryInto;
use std::num::TryFromIntError;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::ledger::gas::{GasMetering, TxGasMeter};
use namada_core::types::internal::KeyVal;
use thiserror::Error;

#[cfg(feature = "wasm-runtime")]
use super::wasm::TxCache;
#[cfg(feature = "wasm-runtime")]
use super::wasm::VpCache;
use super::WasmCacheAccess;
use crate::ledger::gas::{self, VpGasMeter, STORAGE_ACCESS_GAS_PER_BYTE};
use crate::ledger::storage::write_log::{self, WriteLog};
use crate::ledger::storage::{self, Storage, StorageHasher};
use crate::ledger::vp_host_fns;
use crate::proto::Tx;
use crate::types::address::{self, Address};
use crate::types::hash::Hash;
use crate::types::ibc::IbcEvent;
use crate::types::internal::HostEnvResult;
use crate::types::storage::{BlockHeight, Key, TxIndex};
use crate::types::token::{
    is_any_minted_balance_key, is_any_minter_key, is_any_token_balance_key,
};
use crate::vm::memory::VmMemory;
use crate::vm::prefix_iter::{PrefixIteratorId, PrefixIterators};
use crate::vm::{HostRef, MutHostRef};

/// These runtime errors will abort tx WASM execution immediately
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum TxRuntimeError {
    #[error("Out of gas: {0}")]
    OutOfGas(gas::Error),
    #[error("Trying to modify storage for an address that doesn't exit {0}")]
    UnknownAddressStorageModification(Address),
    #[error(
        "Trying to use a validity predicate with an invalid WASM code hash {0}"
    )]
    InvalidVpCodeHash(String),
    #[error("A validity predicate of an account cannot be deleted")]
    CannotDeleteVp,
    #[error("Storage modification error: {0}")]
    StorageModificationError(write_log::Error),
    #[error("Storage error: {0}")]
    StorageError(storage::Error),
    #[error("Storage data error: {0}")]
    StorageDataError(crate::types::storage::Error),
    #[error("Encoding error: {0}")]
    EncodingError(std::io::Error),
    #[error("Address error: {0}")]
    AddressError(address::DecodeError),
    #[error("Numeric conversion error: {0}")]
    NumConversionError(TryFromIntError),
    #[error("Memory error: {0}")]
    MemoryError(Box<dyn std::error::Error + Sync + Send + 'static>),
    #[error("Missing tx data")]
    MissingTxData,
    #[error("IBC: {0}")]
    Ibc(#[from] namada_core::ledger::ibc::Error),
}

type TxResult<T> = std::result::Result<T, TxRuntimeError>;

/// A transaction's host environment
pub struct TxVmEnv<'a, MEM, DB, H, CA>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    /// The VM memory for bi-directional data passing
    pub memory: MEM,
    /// The tx context contains references to host structures.
    pub ctx: TxCtx<'a, DB, H, CA>,
}

/// A transaction's host context
#[derive(Debug)]
pub struct TxCtx<'a, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    /// Read-only access to the storage.
    pub storage: HostRef<'a, &'a Storage<DB, H>>,
    /// Read/write access to the write log.
    pub write_log: MutHostRef<'a, &'a WriteLog>,
    /// Storage prefix iterators.
    pub iterators: MutHostRef<'a, &'a PrefixIterators<'a, DB>>,
    /// Transaction gas meter.
    pub gas_meter: MutHostRef<'a, &'a TxGasMeter>,
    /// The transaction code is used for signature verification
    pub tx: HostRef<'a, &'a Tx>,
    /// The transaction index is used to identify a shielded transaction's
    /// parent
    pub tx_index: HostRef<'a, &'a TxIndex>,
    /// The verifiers whose validity predicates should be triggered.
    pub verifiers: MutHostRef<'a, &'a BTreeSet<Address>>,
    /// Cache for 2-step reads from host environment.
    pub result_buffer: MutHostRef<'a, &'a Option<Vec<u8>>>,
    /// VP WASM compilation cache (this is available in tx context, because
    /// we're pre-compiling VPs from [`tx_init_account`])
    #[cfg(feature = "wasm-runtime")]
    pub vp_wasm_cache: MutHostRef<'a, &'a VpCache<CA>>,
    /// Tx WASM compilation cache
    #[cfg(feature = "wasm-runtime")]
    pub tx_wasm_cache: MutHostRef<'a, &'a TxCache<CA>>,
    /// To avoid unused parameter without "wasm-runtime" feature
    #[cfg(not(feature = "wasm-runtime"))]
    pub cache_access: std::marker::PhantomData<CA>,
}

impl<'a, MEM, DB, H, CA> TxVmEnv<'a, MEM, DB, H, CA>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    /// Create a new environment for transaction execution.
    ///
    /// # Safety
    ///
    /// The way the arguments to this function are used is not thread-safe,
    /// we're assuming single-threaded tx execution with exclusive access to the
    /// mutable references.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        memory: MEM,
        storage: &Storage<DB, H>,
        write_log: &mut WriteLog,
        iterators: &mut PrefixIterators<'a, DB>,
        gas_meter: &mut TxGasMeter,
        tx: &Tx,
        tx_index: &TxIndex,
        verifiers: &mut BTreeSet<Address>,
        result_buffer: &mut Option<Vec<u8>>,
        #[cfg(feature = "wasm-runtime")] vp_wasm_cache: &mut VpCache<CA>,
        #[cfg(feature = "wasm-runtime")] tx_wasm_cache: &mut TxCache<CA>,
    ) -> Self {
        let storage = unsafe { HostRef::new(storage) };
        let write_log = unsafe { MutHostRef::new(write_log) };
        let iterators = unsafe { MutHostRef::new(iterators) };
        let gas_meter = unsafe { MutHostRef::new(gas_meter) };
        let tx = unsafe { HostRef::new(tx) };
        let tx_index = unsafe { HostRef::new(tx_index) };
        let verifiers = unsafe { MutHostRef::new(verifiers) };
        let result_buffer = unsafe { MutHostRef::new(result_buffer) };
        #[cfg(feature = "wasm-runtime")]
        let vp_wasm_cache = unsafe { MutHostRef::new(vp_wasm_cache) };
        #[cfg(feature = "wasm-runtime")]
        let tx_wasm_cache = unsafe { MutHostRef::new(tx_wasm_cache) };
        let ctx = TxCtx {
            storage,
            write_log,
            iterators,
            gas_meter,
            tx,
            tx_index,
            verifiers,
            result_buffer,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache,
            #[cfg(feature = "wasm-runtime")]
            tx_wasm_cache,
            #[cfg(not(feature = "wasm-runtime"))]
            cache_access: std::marker::PhantomData,
        };

        Self { memory, ctx }
    }
}

impl<MEM, DB, H, CA> Clone for TxVmEnv<'_, MEM, DB, H, CA>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    fn clone(&self) -> Self {
        Self {
            memory: self.memory.clone(),
            ctx: self.ctx.clone(),
        }
    }
}

impl<'a, DB, H, CA> Clone for TxCtx<'a, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            write_log: self.write_log.clone(),
            iterators: self.iterators.clone(),
            gas_meter: self.gas_meter.clone(),
            tx: self.tx.clone(),
            tx_index: self.tx_index.clone(),
            verifiers: self.verifiers.clone(),
            result_buffer: self.result_buffer.clone(),
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache: self.vp_wasm_cache.clone(),
            #[cfg(feature = "wasm-runtime")]
            tx_wasm_cache: self.tx_wasm_cache.clone(),
            #[cfg(not(feature = "wasm-runtime"))]
            cache_access: std::marker::PhantomData,
        }
    }
}

/// A validity predicate's host environment
pub struct VpVmEnv<'a, MEM, DB, H, EVAL, CA>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    /// The VM memory for bi-directional data passing
    pub memory: MEM,
    /// The VP context contains references to host structures.
    pub ctx: VpCtx<'a, DB, H, EVAL, CA>,
}

/// A validity predicate's host context
pub struct VpCtx<'a, DB, H, EVAL, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    /// The address of the account that owns the VP
    pub address: HostRef<'a, &'a Address>,
    /// Read-only access to the storage.
    pub storage: HostRef<'a, &'a Storage<DB, H>>,
    /// Read-only access to the write log.
    pub write_log: HostRef<'a, &'a WriteLog>,
    /// Storage prefix iterators.
    pub iterators: MutHostRef<'a, &'a PrefixIterators<'a, DB>>,
    /// VP gas meter.
    pub gas_meter: MutHostRef<'a, &'a VpGasMeter>,
    /// The transaction code is used for signature verification
    pub tx: HostRef<'a, &'a Tx>,
    /// The transaction index is used to identify a shielded transaction's
    /// parent
    pub tx_index: HostRef<'a, &'a TxIndex>,
    /// The runner of the [`vp_eval`] function
    pub eval_runner: HostRef<'a, &'a EVAL>,
    /// Cache for 2-step reads from host environment.
    pub result_buffer: MutHostRef<'a, &'a Option<Vec<u8>>>,
    /// The storage keys that have been changed. Used for calls to `eval`.
    pub keys_changed: HostRef<'a, &'a BTreeSet<Key>>,
    /// The verifiers whose validity predicates should be triggered. Used for
    /// calls to `eval`.
    pub verifiers: HostRef<'a, &'a BTreeSet<Address>>,
    /// VP WASM compilation cache
    #[cfg(feature = "wasm-runtime")]
    pub vp_wasm_cache: MutHostRef<'a, &'a VpCache<CA>>,
    /// To avoid unused parameter without "wasm-runtime" feature
    #[cfg(not(feature = "wasm-runtime"))]
    pub cache_access: std::marker::PhantomData<CA>,
}

/// A Validity predicate runner for calls from the [`vp_eval`] function.
pub trait VpEvaluator {
    /// Storage DB type
    type Db: storage::DB + for<'iter> storage::DBIter<'iter>;
    /// Storage hasher type
    type H: StorageHasher;
    /// Recursive VP evaluator type
    type Eval: VpEvaluator;
    /// WASM compilation cache access
    type CA: WasmCacheAccess;

    /// Evaluate a given validity predicate code with the given input data.
    /// Currently, we can only evaluate VPs using WASM runner with WASM memory.
    ///
    /// Invariant: Calling `VpEvalRunner::eval` from the VP is synchronous as it
    /// shares mutable access to the host context with the VP.
    fn eval(
        &self,
        ctx: VpCtx<'static, Self::Db, Self::H, Self::Eval, Self::CA>,
        vp_code_hash: Hash,
        input_data: Tx,
    ) -> HostEnvResult;
}

impl<'a, MEM, DB, H, EVAL, CA> VpVmEnv<'a, MEM, DB, H, EVAL, CA>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    /// Create a new environment for validity predicate execution.
    ///
    /// # Safety
    ///
    /// The way the arguments to this function are used is not thread-safe,
    /// we're assuming multi-threaded VP execution, but with with exclusive
    /// access to the mutable references (no shared access).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        memory: MEM,
        address: &Address,
        storage: &Storage<DB, H>,
        write_log: &WriteLog,
        gas_meter: &mut VpGasMeter,
        tx: &Tx,
        tx_index: &TxIndex,
        iterators: &mut PrefixIterators<'a, DB>,
        verifiers: &BTreeSet<Address>,
        result_buffer: &mut Option<Vec<u8>>,
        keys_changed: &BTreeSet<Key>,
        eval_runner: &EVAL,
        #[cfg(feature = "wasm-runtime")] vp_wasm_cache: &mut VpCache<CA>,
    ) -> Self {
        let ctx = VpCtx::new(
            address,
            storage,
            write_log,
            gas_meter,
            tx,
            tx_index,
            iterators,
            verifiers,
            result_buffer,
            keys_changed,
            eval_runner,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache,
        );

        Self { memory, ctx }
    }
}

impl<MEM, DB, H, EVAL, CA> Clone for VpVmEnv<'_, MEM, DB, H, EVAL, CA>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    fn clone(&self) -> Self {
        Self {
            memory: self.memory.clone(),
            ctx: self.ctx.clone(),
        }
    }
}

impl<'a, DB, H, EVAL, CA> VpCtx<'a, DB, H, EVAL, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    /// Create a new context for validity predicate execution.
    ///
    /// # Safety
    ///
    /// The way the arguments to this function are used is not thread-safe,
    /// we're assuming multi-threaded VP execution, but with with exclusive
    /// access to the mutable references (no shared access).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: &Address,
        storage: &Storage<DB, H>,
        write_log: &WriteLog,
        gas_meter: &mut VpGasMeter,
        tx: &Tx,
        tx_index: &TxIndex,
        iterators: &mut PrefixIterators<'a, DB>,
        verifiers: &BTreeSet<Address>,
        result_buffer: &mut Option<Vec<u8>>,
        keys_changed: &BTreeSet<Key>,
        eval_runner: &EVAL,
        #[cfg(feature = "wasm-runtime")] vp_wasm_cache: &mut VpCache<CA>,
    ) -> Self {
        let address = unsafe { HostRef::new(address) };
        let storage = unsafe { HostRef::new(storage) };
        let write_log = unsafe { HostRef::new(write_log) };
        let tx = unsafe { HostRef::new(tx) };
        let tx_index = unsafe { HostRef::new(tx_index) };
        let iterators = unsafe { MutHostRef::new(iterators) };
        let gas_meter = unsafe { MutHostRef::new(gas_meter) };
        let verifiers = unsafe { HostRef::new(verifiers) };
        let result_buffer = unsafe { MutHostRef::new(result_buffer) };
        let keys_changed = unsafe { HostRef::new(keys_changed) };
        let eval_runner = unsafe { HostRef::new(eval_runner) };
        #[cfg(feature = "wasm-runtime")]
        let vp_wasm_cache = unsafe { MutHostRef::new(vp_wasm_cache) };
        Self {
            address,
            storage,
            write_log,
            iterators,
            gas_meter,
            tx,
            tx_index,
            eval_runner,
            result_buffer,
            keys_changed,
            verifiers,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache,
            #[cfg(not(feature = "wasm-runtime"))]
            cache_access: std::marker::PhantomData,
        }
    }
}

impl<'a, DB, H, EVAL, CA> Clone for VpCtx<'a, DB, H, EVAL, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    fn clone(&self) -> Self {
        Self {
            address: self.address.clone(),
            storage: self.storage.clone(),
            write_log: self.write_log.clone(),
            iterators: self.iterators.clone(),
            gas_meter: self.gas_meter.clone(),
            tx: self.tx.clone(),
            tx_index: self.tx_index.clone(),
            eval_runner: self.eval_runner.clone(),
            result_buffer: self.result_buffer.clone(),
            keys_changed: self.keys_changed.clone(),
            verifiers: self.verifiers.clone(),
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache: self.vp_wasm_cache.clone(),
            #[cfg(not(feature = "wasm-runtime"))]
            cache_access: std::marker::PhantomData,
        }
    }
}

/// Add a gas cost incured in a transaction
pub fn tx_charge_gas<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    used_gas: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    // if we run out of gas, we need to stop the execution
    let result = gas_meter
        .consume(used_gas)
        .map_err(TxRuntimeError::OutOfGas);
    if let Err(err) = &result {
        tracing::info!(
            "Stopping transaction execution because of gas error: {}",
            err
        );
    }
    result
}

/// Called from VP wasm to request to use the given gas amount
pub fn vp_charge_gas<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    used_gas: u64,
) -> vp_host_fns::EnvResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    vp_host_fns::add_gas(gas_meter, used_gas)
}

/// Storage `has_key` function exposed to the wasm VM Tx environment. It will
/// try to check the write log first and if no entry found then the storage.
pub fn tx_has_key<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    key_ptr: u64,
    key_len: u64,
) -> TxResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;

    tracing::debug!("tx_has_key {}, key {}", key, key_ptr,);

    let key = Key::parse(key).map_err(TxRuntimeError::StorageDataError)?;

    // try to read from the write log first
    let write_log = unsafe { env.ctx.write_log.get() };
    let (log_val, gas) = write_log.read(&key);
    tx_charge_gas(env, gas)?;
    Ok(match log_val {
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
        Some(&write_log::StorageModification::Temp { .. }) => {
            HostEnvResult::Success.to_i64()
        }
        None => {
            // when not found in write log, try to check the storage
            let storage = unsafe { env.ctx.storage.get() };
            let (present, gas) = storage
                .has_key(&key)
                .map_err(TxRuntimeError::StorageError)?;
            tx_charge_gas(env, gas)?;
            HostEnvResult::from(present).to_i64()
        }
    })
}

/// Storage read function exposed to the wasm VM Tx environment. It will try to
/// read from the write log first and if no entry found then from the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn tx_read<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    key_ptr: u64,
    key_len: u64,
) -> TxResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;

    tracing::debug!("tx_read {}, key {}", key, key_ptr,);

    let key = Key::parse(key).map_err(TxRuntimeError::StorageDataError)?;

    // try to read from the write log first
    let write_log = unsafe { env.ctx.write_log.get() };
    let (log_val, gas) = write_log.read(&key);
    tx_charge_gas(env, gas)?;
    Ok(match log_val {
        Some(write_log::StorageModification::Write { ref value }) => {
            let len: i64 = value
                .len()
                .try_into()
                .map_err(TxRuntimeError::NumConversionError)?;
            let result_buffer = unsafe { env.ctx.result_buffer.get() };
            result_buffer.replace(value.clone());
            len
        }
        Some(&write_log::StorageModification::Delete) => {
            // fail, given key has been deleted
            HostEnvResult::Fail.to_i64()
        }
        Some(write_log::StorageModification::InitAccount {
            ref vp_code_hash,
        }) => {
            // read the VP of a new account
            let len: i64 = vp_code_hash
                .len()
                .try_into()
                .map_err(TxRuntimeError::NumConversionError)?;
            let result_buffer = unsafe { env.ctx.result_buffer.get() };
            result_buffer.replace(vp_code_hash.to_vec());
            len
        }
        Some(write_log::StorageModification::Temp { ref value }) => {
            let len: i64 = value
                .len()
                .try_into()
                .map_err(TxRuntimeError::NumConversionError)?;
            let result_buffer = unsafe { env.ctx.result_buffer.get() };
            result_buffer.replace(value.clone());
            len
        }
        None => {
            // when not found in write log, try to read from the storage
            let storage = unsafe { env.ctx.storage.get() };
            let (value, gas) =
                storage.read(&key).map_err(TxRuntimeError::StorageError)?;
            tx_charge_gas(env, gas)?;
            match value {
                Some(value) => {
                    let len: i64 = value
                        .len()
                        .try_into()
                        .map_err(TxRuntimeError::NumConversionError)?;
                    let result_buffer = unsafe { env.ctx.result_buffer.get() };
                    result_buffer.replace(value);
                    len
                }
                None => HostEnvResult::Fail.to_i64(),
            }
        }
    })
}

/// This function is a helper to handle the first step of reading var-len
/// values from the host.
///
/// In cases where we're reading a value from the host in the guest and
/// we don't know the byte size up-front, we have to read it in 2-steps. The
/// first step reads the value into a result buffer and returns the size (if
/// any) back to the guest, the second step reads the value from cache into a
/// pre-allocated buffer with the obtained size.
pub fn tx_result_buffer<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    result_ptr: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let result_buffer = unsafe { env.ctx.result_buffer.get() };
    let value = result_buffer.take().unwrap();
    let gas = env
        .memory
        .write_bytes(result_ptr, value)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)
}

/// Storage prefix iterator function exposed to the wasm VM Tx environment.
/// It will try to get an iterator from the storage and return the corresponding
/// ID of the iterator, ordered by storage keys.
pub fn tx_iter_prefix<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    prefix_ptr: u64,
    prefix_len: u64,
) -> TxResult<u64>
where
    MEM: VmMemory,
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let (prefix, gas) = env
        .memory
        .read_string(prefix_ptr, prefix_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;

    tracing::debug!("tx_iter_prefix {}", prefix);

    let prefix =
        Key::parse(prefix).map_err(TxRuntimeError::StorageDataError)?;

    let write_log = unsafe { env.ctx.write_log.get() };
    let storage = unsafe { env.ctx.storage.get() };
    let (iter, gas) = storage::iter_prefix_post(write_log, storage, &prefix);
    tx_charge_gas(env, gas)?;

    let iterators = unsafe { env.ctx.iterators.get() };
    Ok(iterators.insert(iter).id())
}

/// Storage prefix iterator next function exposed to the wasm VM Tx environment.
/// It will try to read from the write log first and if no entry found then from
/// the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn tx_iter_next<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    iter_id: u64,
) -> TxResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    tracing::debug!("tx_iter_next iter_id {}", iter_id,);

    let write_log = unsafe { env.ctx.write_log.get() };
    let iterators = unsafe { env.ctx.iterators.get() };
    let iter_id = PrefixIteratorId::new(iter_id);
    while let Some((key, val, iter_gas)) = iterators.next(iter_id) {
        let (log_val, log_gas) = write_log.read(
            &Key::parse(key.clone())
                .map_err(TxRuntimeError::StorageDataError)?,
        );
        tx_charge_gas(env, iter_gas + log_gas)?;
        match log_val {
            Some(write_log::StorageModification::Write { ref value }) => {
                let key_val = KeyVal {
                    key,
                    val: value.clone(),
                }
                .try_to_vec()
                .map_err(TxRuntimeError::EncodingError)?;
                let len: i64 = key_val
                    .len()
                    .try_into()
                    .map_err(TxRuntimeError::NumConversionError)?;
                let result_buffer = unsafe { env.ctx.result_buffer.get() };
                result_buffer.replace(key_val);
                return Ok(len);
            }
            Some(&write_log::StorageModification::Delete) => {
                // check the next because the key has already deleted
                continue;
            }
            Some(&write_log::StorageModification::InitAccount { .. }) => {
                // a VP of a new account doesn't need to be iterated
                continue;
            }
            Some(write_log::StorageModification::Temp { ref value }) => {
                let key_val = KeyVal {
                    key,
                    val: value.clone(),
                }
                .try_to_vec()
                .map_err(TxRuntimeError::EncodingError)?;
                let len: i64 = key_val
                    .len()
                    .try_into()
                    .map_err(TxRuntimeError::NumConversionError)?;
                let result_buffer = unsafe { env.ctx.result_buffer.get() };
                result_buffer.replace(key_val);
                return Ok(len);
            }
            None => {
                let key_val = KeyVal { key, val }
                    .try_to_vec()
                    .map_err(TxRuntimeError::EncodingError)?;
                let len: i64 = key_val
                    .len()
                    .try_into()
                    .map_err(TxRuntimeError::NumConversionError)?;
                let result_buffer = unsafe { env.ctx.result_buffer.get() };
                result_buffer.replace(key_val);
                return Ok(len);
            }
        }
    }
    Ok(HostEnvResult::Fail.to_i64())
}

/// Storage write function exposed to the wasm VM Tx environment. The given
/// key/value will be written to the write log.
pub fn tx_write<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;
    let (value, gas) = env
        .memory
        .read_bytes(val_ptr, val_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;

    tracing::debug!("tx_update {}, {:?}", key, value);

    let key = Key::parse(key).map_err(TxRuntimeError::StorageDataError)?;
    if key.is_validity_predicate().is_some() {
        tx_validate_vp_code_hash(env, &value)?;
    }

    check_address_existence(env, &key)?;

    let write_log = unsafe { env.ctx.write_log.get() };
    let (gas, _size_diff) = write_log
        .write(&key, value)
        .map_err(TxRuntimeError::StorageModificationError)?;
    tx_charge_gas(env, gas)
}

/// Temporary storage write function exposed to the wasm VM Tx environment. The
/// given key/value will be written only to the write log. It will be never
/// written to the storage.
pub fn tx_write_temp<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;
    let (value, gas) = env
        .memory
        .read_bytes(val_ptr, val_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;

    tracing::debug!("tx_write_temp {}, {:?}", key, value);

    let key = Key::parse(key).map_err(TxRuntimeError::StorageDataError)?;

    check_address_existence(env, &key)?;

    let write_log = unsafe { env.ctx.write_log.get() };
    let (gas, _size_diff) = write_log
        .write_temp(&key, value)
        .map_err(TxRuntimeError::StorageModificationError)?;
    tx_charge_gas(env, gas)
}

fn check_address_existence<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    key: &Key,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    // Get the token if the key is a balance or minter key
    let token = if let Some([token, _]) = is_any_token_balance_key(key) {
        Some(token)
    } else {
        is_any_minted_balance_key(key).or_else(|| is_any_minter_key(key))
    };

    let write_log = unsafe { env.ctx.write_log.get() };
    let storage = unsafe { env.ctx.storage.get() };
    for addr in key.find_addresses() {
        // skip if the address is a token address
        if Some(&addr) == token {
            continue;
        }
        // skip the check for implicit and internal addresses
        if let Address::Implicit(_) | Address::Internal(_) = &addr {
            continue;
        }
        let vp_key = Key::validity_predicate(&addr);
        let (vp, gas) = write_log.read(&vp_key);
        tx_charge_gas(env, gas)?;
        // just check the existence because the write log should not have the
        // delete log of the VP
        if vp.is_none() {
            let (is_present, gas) = storage
                .has_key(&vp_key)
                .map_err(TxRuntimeError::StorageError)?;
            tx_charge_gas(env, gas)?;
            if !is_present {
                tracing::info!(
                    "Trying to write into storage with a key containing an \
                     address that doesn't exist: {}",
                    addr
                );
                return Err(TxRuntimeError::UnknownAddressStorageModification(
                    addr,
                ));
            }
        }
    }
    Ok(())
}

/// Storage delete function exposed to the wasm VM Tx environment. The given
/// key/value will be written as deleted to the write log.
pub fn tx_delete<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    key_ptr: u64,
    key_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;

    tracing::debug!("tx_delete {}", key);

    let key = Key::parse(key).map_err(TxRuntimeError::StorageDataError)?;
    if key.is_validity_predicate().is_some() {
        return Err(TxRuntimeError::CannotDeleteVp);
    }

    let write_log = unsafe { env.ctx.write_log.get() };
    let (gas, _size_diff) = write_log
        .delete(&key)
        .map_err(TxRuntimeError::StorageModificationError)?;
    tx_charge_gas(env, gas)
}

/// Emitting an IBC event function exposed to the wasm VM Tx environment.
/// The given IBC event will be set to the write log.
pub fn tx_emit_ibc_event<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    event_ptr: u64,
    event_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let (event, gas) = env
        .memory
        .read_bytes(event_ptr, event_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;
    let event: IbcEvent = BorshDeserialize::try_from_slice(&event)
        .map_err(TxRuntimeError::EncodingError)?;
    let write_log = unsafe { env.ctx.write_log.get() };
    let gas = write_log.emit_ibc_event(event);
    tx_charge_gas(env, gas)
}

/// Getting an IBC event function exposed to the wasm VM Tx environment.
pub fn tx_get_ibc_event<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    event_type_ptr: u64,
    event_type_len: u64,
) -> TxResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let (event_type, gas) = env
        .memory
        .read_string(event_type_ptr, event_type_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;
    let write_log = unsafe { env.ctx.write_log.get() };
    for event in write_log.get_ibc_events() {
        if event.event_type == event_type {
            let value =
                event.try_to_vec().map_err(TxRuntimeError::EncodingError)?;
            let len: i64 = value
                .len()
                .try_into()
                .map_err(TxRuntimeError::NumConversionError)?;
            let result_buffer = unsafe { env.ctx.result_buffer.get() };
            result_buffer.replace(value);
            return Ok(len);
        }
    }
    Ok(HostEnvResult::Fail.to_i64())
}

/// Storage read prior state (before tx execution) function exposed to the wasm
/// VM VP environment. It will try to read from the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn vp_read_pre<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    key_ptr: u64,
    key_len: u64,
) -> vp_host_fns::EnvResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    vp_host_fns::add_gas(gas_meter, gas)?;

    // try to read from the storage
    let key =
        Key::parse(key).map_err(vp_host_fns::RuntimeError::StorageDataError)?;
    let storage = unsafe { env.ctx.storage.get() };
    let write_log = unsafe { env.ctx.write_log.get() };
    let value = vp_host_fns::read_pre(gas_meter, storage, write_log, &key)?;
    tracing::debug!(
        "vp_read_pre addr {}, key {}, value {:?}",
        unsafe { env.ctx.address.get() },
        key,
        value,
    );
    Ok(match value {
        Some(value) => {
            let len: i64 = value
                .len()
                .try_into()
                .map_err(vp_host_fns::RuntimeError::NumConversionError)?;
            let result_buffer = unsafe { env.ctx.result_buffer.get() };
            result_buffer.replace(value);
            len
        }
        None => HostEnvResult::Fail.to_i64(),
    })
}

/// Storage read posterior state (after tx execution) function exposed to the
/// wasm VM VP environment. It will try to read from the write log first and if
/// no entry found then from the storage.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn vp_read_post<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    key_ptr: u64,
    key_len: u64,
) -> vp_host_fns::EnvResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    vp_host_fns::add_gas(gas_meter, gas)?;

    tracing::debug!("vp_read_post {}, key {}", key, key_ptr,);

    // try to read from the write log first
    let key =
        Key::parse(key).map_err(vp_host_fns::RuntimeError::StorageDataError)?;
    let storage = unsafe { env.ctx.storage.get() };
    let write_log = unsafe { env.ctx.write_log.get() };
    let value = vp_host_fns::read_post(gas_meter, storage, write_log, &key)?;
    Ok(match value {
        Some(value) => {
            let len: i64 = value
                .len()
                .try_into()
                .map_err(vp_host_fns::RuntimeError::NumConversionError)?;
            let result_buffer = unsafe { env.ctx.result_buffer.get() };
            result_buffer.replace(value);
            len
        }
        None => HostEnvResult::Fail.to_i64(),
    })
}

/// Storage read temporary state (after tx execution) function exposed to the
/// wasm VM VP environment. It will try to read from only the write log.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn vp_read_temp<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    key_ptr: u64,
    key_len: u64,
) -> vp_host_fns::EnvResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    vp_host_fns::add_gas(gas_meter, gas)?;

    tracing::debug!("vp_read_temp {}, key {}", key, key_ptr);

    // try to read from the write log
    let key =
        Key::parse(key).map_err(vp_host_fns::RuntimeError::StorageDataError)?;
    let write_log = unsafe { env.ctx.write_log.get() };
    let value = vp_host_fns::read_temp(gas_meter, write_log, &key)?;
    Ok(match value {
        Some(value) => {
            let len: i64 = value
                .len()
                .try_into()
                .map_err(vp_host_fns::RuntimeError::NumConversionError)?;
            let result_buffer = unsafe { env.ctx.result_buffer.get() };
            result_buffer.replace(value);
            len
        }
        None => HostEnvResult::Fail.to_i64(),
    })
}

/// This function is a helper to handle the first step of reading var-len
/// values from the host.
///
/// In cases where we're reading a value from the host in the guest and
/// we don't know the byte size up-front, we have to read it in 2-steps. The
/// first step reads the value into a result buffer and returns the size (if
/// any) back to the guest, the second step reads the value from cache into a
/// pre-allocated buffer with the obtained size.
pub fn vp_result_buffer<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    result_ptr: u64,
) -> vp_host_fns::EnvResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let result_buffer = unsafe { env.ctx.result_buffer.get() };
    let value = result_buffer.take().unwrap();
    let gas = env
        .memory
        .write_bytes(result_ptr, value)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    vp_host_fns::add_gas(gas_meter, gas)
}

/// Storage `has_key` in prior state (before tx execution) function exposed to
/// the wasm VM VP environment. It will try to read from the storage.
pub fn vp_has_key_pre<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    key_ptr: u64,
    key_len: u64,
) -> vp_host_fns::EnvResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    vp_host_fns::add_gas(gas_meter, gas)?;

    tracing::debug!("vp_has_key_pre {}, key {}", key, key_ptr,);

    let key =
        Key::parse(key).map_err(vp_host_fns::RuntimeError::StorageDataError)?;
    let storage = unsafe { env.ctx.storage.get() };
    let write_log = unsafe { env.ctx.write_log.get() };
    let present =
        vp_host_fns::has_key_pre(gas_meter, storage, write_log, &key)?;
    Ok(HostEnvResult::from(present).to_i64())
}

/// Storage `has_key` in posterior state (after tx execution) function exposed
/// to the wasm VM VP environment. It will try to check the write log first and
/// if no entry found then the storage.
pub fn vp_has_key_post<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    key_ptr: u64,
    key_len: u64,
) -> vp_host_fns::EnvResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (key, gas) = env
        .memory
        .read_string(key_ptr, key_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    vp_host_fns::add_gas(gas_meter, gas)?;

    tracing::debug!("vp_has_key_post {}, key {}", key, key_ptr,);

    let key =
        Key::parse(key).map_err(vp_host_fns::RuntimeError::StorageDataError)?;
    let storage = unsafe { env.ctx.storage.get() };
    let write_log = unsafe { env.ctx.write_log.get() };
    let present =
        vp_host_fns::has_key_post(gas_meter, storage, write_log, &key)?;
    Ok(HostEnvResult::from(present).to_i64())
}

/// Storage prefix iterator function for prior state (before tx execution)
/// exposed to the wasm VM VP environment. It will try to get an iterator from
/// the storage and return the corresponding ID of the iterator, ordered by
/// storage keys.
pub fn vp_iter_prefix_pre<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    prefix_ptr: u64,
    prefix_len: u64,
) -> vp_host_fns::EnvResult<u64>
where
    MEM: VmMemory,
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (prefix, gas) = env
        .memory
        .read_string(prefix_ptr, prefix_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    vp_host_fns::add_gas(gas_meter, gas)?;

    tracing::debug!("vp_iter_prefix_pre {}", prefix);

    let prefix = Key::parse(prefix)
        .map_err(vp_host_fns::RuntimeError::StorageDataError)?;

    let write_log = unsafe { env.ctx.write_log.get() };
    let storage = unsafe { env.ctx.storage.get() };
    let iter =
        vp_host_fns::iter_prefix_pre(gas_meter, write_log, storage, &prefix)?;

    let iterators = unsafe { env.ctx.iterators.get() };
    Ok(iterators.insert(iter).id())
}

/// Storage prefix iterator function for posterior state (after tx execution)
/// exposed to the wasm VM VP environment. It will try to get an iterator from
/// the storage and return the corresponding ID of the iterator, ordered by
/// storage keys.
pub fn vp_iter_prefix_post<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    prefix_ptr: u64,
    prefix_len: u64,
) -> vp_host_fns::EnvResult<u64>
where
    MEM: VmMemory,
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (prefix, gas) = env
        .memory
        .read_string(prefix_ptr, prefix_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    vp_host_fns::add_gas(gas_meter, gas)?;

    tracing::debug!("vp_iter_prefix_post {}", prefix);

    let prefix = Key::parse(prefix)
        .map_err(vp_host_fns::RuntimeError::StorageDataError)?;

    let write_log = unsafe { env.ctx.write_log.get() };
    let storage = unsafe { env.ctx.storage.get() };
    let iter =
        vp_host_fns::iter_prefix_post(gas_meter, write_log, storage, &prefix)?;

    let iterators = unsafe { env.ctx.iterators.get() };
    Ok(iterators.insert(iter).id())
}

/// Storage prefix iterator for prior or posterior state function
/// exposed to the wasm VM VP environment.
///
/// Returns `-1` when the key is not present, or the length of the data when
/// the key is present (the length may be `0`).
pub fn vp_iter_next<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    iter_id: u64,
) -> vp_host_fns::EnvResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    tracing::debug!("vp_iter_next iter_id {}", iter_id);

    let iterators = unsafe { env.ctx.iterators.get() };
    let iter_id = PrefixIteratorId::new(iter_id);
    if let Some(iter) = iterators.get_mut(iter_id) {
        let gas_meter = unsafe { env.ctx.gas_meter.get() };
        if let Some((key, val)) = vp_host_fns::iter_next(gas_meter, iter)? {
            let key_val = KeyVal { key, val }
                .try_to_vec()
                .map_err(vp_host_fns::RuntimeError::EncodingError)?;
            let len: i64 = key_val
                .len()
                .try_into()
                .map_err(vp_host_fns::RuntimeError::NumConversionError)?;
            let result_buffer = unsafe { env.ctx.result_buffer.get() };
            result_buffer.replace(key_val);
            return Ok(len);
        }
    }
    Ok(HostEnvResult::Fail.to_i64())
}

/// Verifier insertion function exposed to the wasm VM Tx environment.
pub fn tx_insert_verifier<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    addr_ptr: u64,
    addr_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let (addr, gas) = env
        .memory
        .read_string(addr_ptr, addr_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;

    tracing::debug!("tx_insert_verifier {}, addr_ptr {}", addr, addr_ptr,);

    let addr = Address::decode(&addr).map_err(TxRuntimeError::AddressError)?;

    let verifiers = unsafe { env.ctx.verifiers.get() };
    verifiers.insert(addr);
    // This is not a storage write, use the same multiplier used for a storage
    // read
    tx_charge_gas(env, addr_len * STORAGE_ACCESS_GAS_PER_BYTE)
}

/// Update a validity predicate function exposed to the wasm VM Tx environment
pub fn tx_update_validity_predicate<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    addr_ptr: u64,
    addr_len: u64,
    code_hash_ptr: u64,
    code_hash_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let (addr, gas) = env
        .memory
        .read_string(addr_ptr, addr_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;

    let addr = Address::decode(addr).map_err(TxRuntimeError::AddressError)?;
    tracing::debug!("tx_update_validity_predicate for addr {}", addr);

    let key = Key::validity_predicate(&addr);
    let (code_hash, gas) = env
        .memory
        .read_bytes(code_hash_ptr, code_hash_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;

    tx_validate_vp_code_hash(env, &code_hash)?;

    let write_log = unsafe { env.ctx.write_log.get() };
    let (gas, _size_diff) = write_log
        .write(&key, code_hash)
        .map_err(TxRuntimeError::StorageModificationError)?;
    tx_charge_gas(env, gas)
}

/// Initialize a new account established address.
pub fn tx_init_account<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    code_hash_ptr: u64,
    code_hash_len: u64,
    result_ptr: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let (code_hash, gas) = env
        .memory
        .read_bytes(code_hash_ptr, code_hash_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)?;

    tx_validate_vp_code_hash(env, &code_hash)?;

    tracing::debug!("tx_init_account");

    let storage = unsafe { env.ctx.storage.get() };
    let write_log = unsafe { env.ctx.write_log.get() };
    let code_hash = Hash::try_from(&code_hash[..])
        .map_err(|e| TxRuntimeError::InvalidVpCodeHash(e.to_string()))?;
    let (addr, gas) = write_log.init_account(&storage.address_gen, code_hash);
    let addr_bytes =
        addr.try_to_vec().map_err(TxRuntimeError::EncodingError)?;
    tx_charge_gas(env, gas)?;
    let gas = env
        .memory
        .write_bytes(result_ptr, addr_bytes)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)
}

/// Getting the chain ID function exposed to the wasm VM Tx environment.
pub fn tx_get_chain_id<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    result_ptr: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let storage = unsafe { env.ctx.storage.get() };
    let (chain_id, gas) = storage.get_chain_id();
    tx_charge_gas(env, gas)?;
    let gas = env
        .memory
        .write_string(result_ptr, chain_id)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)
}

/// Getting the block height function exposed to the wasm VM Tx
/// environment. The height is that of the block to which the current
/// transaction is being applied.
pub fn tx_get_block_height<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
) -> TxResult<u64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let storage = unsafe { env.ctx.storage.get() };
    let (height, gas) = storage.get_block_height();
    tx_charge_gas(env, gas)?;
    Ok(height.0)
}

/// Getting the transaction index function exposed to the wasm VM Tx
/// environment. The index is that of the transaction being applied
/// in the current block.
pub fn tx_get_tx_index<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
) -> TxResult<u32>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let tx_index = unsafe { env.ctx.tx_index.get() };
    tx_charge_gas(env, crate::vm::host_env::gas::STORAGE_ACCESS_GAS_PER_BYTE)?;
    Ok(tx_index.0)
}

/// Getting the block height function exposed to the wasm VM VP
/// environment. The height is that of the block to which the current
/// transaction is being applied.
pub fn vp_get_tx_index<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
) -> vp_host_fns::EnvResult<u32>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    let tx_index = unsafe { env.ctx.tx_index.get() };
    let tx_idx = vp_host_fns::get_tx_index(gas_meter, tx_index)?;
    Ok(tx_idx.0)
}

/// Getting the block hash function exposed to the wasm VM Tx environment. The
/// hash is that of the block to which the current transaction is being applied.
pub fn tx_get_block_hash<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    result_ptr: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let storage = unsafe { env.ctx.storage.get() };
    let (hash, gas) = storage.get_block_hash();
    tx_charge_gas(env, gas)?;
    let gas = env
        .memory
        .write_bytes(result_ptr, hash.0)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)
}

/// Getting the block epoch function exposed to the wasm VM Tx
/// environment. The epoch is that of the block to which the current
/// transaction is being applied.
pub fn tx_get_block_epoch<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
) -> TxResult<u64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let storage = unsafe { env.ctx.storage.get() };
    let (epoch, gas) = storage.get_current_epoch();
    tx_charge_gas(env, gas)?;
    Ok(epoch.0)
}

/// Get the native token's address
pub fn tx_get_native_token<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    result_ptr: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let storage = unsafe { env.ctx.storage.get() };
    tx_charge_gas(env, STORAGE_ACCESS_GAS_PER_BYTE)?;
    let native_token = storage.native_token.clone();
    let native_token_string = native_token.encode();
    let gas = env
        .memory
        .write_string(result_ptr, native_token_string)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tx_charge_gas(env, gas)
}

/// Getting the block header function exposed to the wasm VM Tx environment.
pub fn tx_get_block_header<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    height: u64,
) -> TxResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let storage = unsafe { env.ctx.storage.get() };
    let (header, gas) = storage
        .get_block_header(Some(BlockHeight(height)))
        .map_err(TxRuntimeError::StorageError)?;
    Ok(match header {
        Some(h) => {
            let value =
                h.try_to_vec().map_err(TxRuntimeError::EncodingError)?;
            let len: i64 = value
                .len()
                .try_into()
                .map_err(TxRuntimeError::NumConversionError)?;
            let result_buffer = unsafe { env.ctx.result_buffer.get() };
            result_buffer.replace(value);
            tx_charge_gas(env, gas)?;
            len
        }
        None => HostEnvResult::Fail.to_i64(),
    })
}

/// Getting the chain ID function exposed to the wasm VM VP environment.
pub fn vp_get_chain_id<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    result_ptr: u64,
) -> vp_host_fns::EnvResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    let storage = unsafe { env.ctx.storage.get() };
    let chain_id = vp_host_fns::get_chain_id(gas_meter, storage)?;
    let gas = env
        .memory
        .write_string(result_ptr, chain_id)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    vp_host_fns::add_gas(gas_meter, gas)
}

/// Getting the block height function exposed to the wasm VM VP
/// environment. The height is that of the block to which the current
/// transaction is being applied.
pub fn vp_get_block_height<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
) -> vp_host_fns::EnvResult<u64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    let storage = unsafe { env.ctx.storage.get() };
    let height = vp_host_fns::get_block_height(gas_meter, storage)?;
    Ok(height.0)
}

/// Getting the block header function exposed to the wasm VM VP environment.
pub fn vp_get_block_header<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    height: u64,
) -> vp_host_fns::EnvResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    let storage = unsafe { env.ctx.storage.get() };
    let (header, gas) = storage
        .get_block_header(Some(BlockHeight(height)))
        .map_err(vp_host_fns::RuntimeError::StorageError)?;
    vp_host_fns::add_gas(gas_meter, gas)?;
    Ok(match header {
        Some(h) => {
            let value = h
                .try_to_vec()
                .map_err(vp_host_fns::RuntimeError::EncodingError)?;
            let len: i64 = value
                .len()
                .try_into()
                .map_err(vp_host_fns::RuntimeError::NumConversionError)?;
            let result_buffer = unsafe { env.ctx.result_buffer.get() };
            result_buffer.replace(value);
            len
        }
        None => HostEnvResult::Fail.to_i64(),
    })
}

/// Getting the block hash function exposed to the wasm VM VP environment. The
/// hash is that of the block to which the current transaction is being applied.
pub fn vp_get_block_hash<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    result_ptr: u64,
) -> vp_host_fns::EnvResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    let storage = unsafe { env.ctx.storage.get() };
    let hash = vp_host_fns::get_block_hash(gas_meter, storage)?;
    let gas = env
        .memory
        .write_bytes(result_ptr, hash.0)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    vp_host_fns::add_gas(gas_meter, gas)
}

/// Getting the transaction hash function exposed to the wasm VM VP environment.
pub fn vp_get_tx_code_hash<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    result_ptr: u64,
) -> vp_host_fns::EnvResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    let tx = unsafe { env.ctx.tx.get() };
    let hash = vp_host_fns::get_tx_code_hash(gas_meter, tx)?;
    let mut result_bytes = vec![];
    if let Some(hash) = hash {
        result_bytes.push(1);
        result_bytes.extend(hash.0);
    } else {
        result_bytes.push(0);
    };
    let gas = env
        .memory
        .write_bytes(result_ptr, result_bytes)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    vp_host_fns::add_gas(gas_meter, gas)
}

/// Getting the block epoch function exposed to the wasm VM VP
/// environment. The epoch is that of the block to which the current
/// transaction is being applied.
pub fn vp_get_block_epoch<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
) -> vp_host_fns::EnvResult<u64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    let storage = unsafe { env.ctx.storage.get() };
    let epoch = vp_host_fns::get_block_epoch(gas_meter, storage)?;
    Ok(epoch.0)
}

/// Verify a transaction signature
/// TODO: this is just a warkaround to track gas for multiple singature
/// verifications. When the runtime gas meter is implemented, this funcion can
/// be removed
#[allow(clippy::too_many_arguments)]
pub fn vp_verify_tx_section_signature<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    hash_list_ptr: u64,
    hash_list_len: u64,
    public_keys_map_ptr: u64,
    public_keys_map_len: u64,
    signer_ptr: u64,
    signer_len: u64,
    threshold: u8,
    max_signatures_ptr: u64,
    max_signatures_len: u64,
) -> vp_host_fns::EnvResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (hash_list, gas) = env
        .memory
        .read_bytes(hash_list_ptr, hash_list_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;

    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    vp_host_fns::add_gas(gas_meter, gas)?;
    let hashes = <[Hash; 1]>::try_from_slice(&hash_list)
        .map_err(vp_host_fns::RuntimeError::EncodingError)?;

    let (public_keys_map, gas) = env
        .memory
        .read_bytes(public_keys_map_ptr, public_keys_map_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    vp_host_fns::add_gas(gas_meter, gas)?;
    let public_keys_map =
        namada_core::types::account::AccountPublicKeysMap::try_from_slice(
            &public_keys_map,
        )
        .map_err(vp_host_fns::RuntimeError::EncodingError)?;

    let (signer, gas) = env
        .memory
        .read_bytes(signer_ptr, signer_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    vp_host_fns::add_gas(gas_meter, gas)?;
    let signer = Address::try_from_slice(&signer)
        .map_err(vp_host_fns::RuntimeError::EncodingError)?;

    let (max_signatures, gas) = env
        .memory
        .read_bytes(max_signatures_ptr, max_signatures_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    vp_host_fns::add_gas(gas_meter, gas)?;
    let max_signatures = Option::<u8>::try_from_slice(&max_signatures)
        .map_err(vp_host_fns::RuntimeError::EncodingError)?;

    let tx = unsafe { env.ctx.tx.get() };

    Ok(HostEnvResult::from(
        tx.verify_signatures(
            &hashes,
            public_keys_map,
            &Some(signer),
            threshold,
            max_signatures,
            Some(gas_meter),
        )
        .is_ok(),
    )
    .to_i64())
}

/// Verify a ShieldedTransaction.
pub fn vp_verify_masp<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    tx_ptr: u64,
    tx_len: u64,
) -> vp_host_fns::EnvResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    use masp_primitives::transaction::Transaction;

    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    let (tx_bytes, gas) = env
        .memory
        .read_bytes(tx_ptr, tx_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    vp_host_fns::add_gas(gas_meter, gas)?;

    let shielded: Transaction =
        BorshDeserialize::try_from_slice(tx_bytes.as_slice())
            .map_err(vp_host_fns::RuntimeError::EncodingError)?;

    Ok(
        // TODO: once the runtime gas meter is implemented we need to benchmark
        // this funcion and charge the gas here. For the moment, the cost of
        // this is included in the benchmark of the masp vp
        HostEnvResult::from(crate::sdk::masp::verify_shielded_tx(&shielded))
            .to_i64(),
    )
}

/// Log a string from exposed to the wasm VM Tx environment. The message will be
/// printed at the [`tracing::Level::INFO`]. This function is for development
/// only.
pub fn tx_log_string<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    str_ptr: u64,
    str_len: u64,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let (str, _gas) = env
        .memory
        .read_string(str_ptr, str_len as _)
        .map_err(|e| TxRuntimeError::MemoryError(Box::new(e)))?;
    tracing::info!("WASM Transaction log: {}", str);
    Ok(())
}

/// Execute IBC tx.
// Temporarily the IBC tx execution is implemented via a host function to
// workaround wasm issue.
pub fn tx_ibc_execute<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    use std::cell::RefCell;
    use std::rc::Rc;

    use namada_core::ledger::ibc::{IbcActions, TransferModule};

    let tx_data = unsafe { env.ctx.tx.get().data() }
        .ok_or(TxRuntimeError::MissingTxData)?;
    let ctx = Rc::new(RefCell::new(env.ctx.clone()));
    let mut actions = IbcActions::new(ctx.clone());
    let module = TransferModule::new(ctx);
    actions.add_transfer_route(module.module_id(), module);
    actions.execute(&tx_data)?;

    Ok(())
}

/// Validate a VP WASM code hash in a tx environment.
fn tx_validate_vp_code_hash<MEM, DB, H, CA>(
    env: &TxVmEnv<MEM, DB, H, CA>,
    code_hash: &[u8],
) -> TxResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let hash = Hash::try_from(code_hash)
        .map_err(|e| TxRuntimeError::InvalidVpCodeHash(e.to_string()))?;
    let key = Key::wasm_code(&hash);
    let write_log = unsafe { env.ctx.write_log.get() };
    let (result, gas) = write_log.read(&key);
    tx_charge_gas(env, gas)?;
    if result.is_none() {
        let storage = unsafe { env.ctx.storage.get() };
        let (is_present, gas) = storage
            .has_key(&key)
            .map_err(TxRuntimeError::StorageError)?;
        tx_charge_gas(env, gas)?;
        if !is_present {
            return Err(TxRuntimeError::InvalidVpCodeHash(
                "The corresponding VP code doesn't exist".to_string(),
            ));
        }
    }
    Ok(())
}

/// Evaluate a validity predicate with the given input data.
pub fn vp_eval<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<'static, MEM, DB, H, EVAL, CA>,
    vp_code_hash_ptr: u64,
    vp_code_hash_len: u64,
    input_data_ptr: u64,
    input_data_len: u64,
) -> vp_host_fns::EnvResult<i64>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator<Db = DB, H = H, Eval = EVAL, CA = CA>,
    CA: WasmCacheAccess,
{
    let (vp_code_hash, gas) = env
        .memory
        .read_bytes(vp_code_hash_ptr, vp_code_hash_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    vp_host_fns::add_gas(gas_meter, gas)?;

    let (input_data, gas) = env
        .memory
        .read_bytes(input_data_ptr, input_data_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    vp_host_fns::add_gas(gas_meter, gas)?;
    let input_data: Tx = BorshDeserialize::try_from_slice(&input_data)
        .map_err(vp_host_fns::RuntimeError::EncodingError)?;
    let vp_code_hash = Hash(vp_code_hash.try_into().map_err(|e| {
        vp_host_fns::RuntimeError::EncodingError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Not a valid hash: {:?}", e),
        ))
    })?);

    let eval_runner = unsafe { env.ctx.eval_runner.get() };
    Ok(eval_runner
        .eval(env.ctx.clone(), vp_code_hash, input_data)
        .to_i64())
}

/// Get the native token's address
pub fn vp_get_native_token<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    result_ptr: u64,
) -> vp_host_fns::EnvResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let gas_meter = unsafe { env.ctx.gas_meter.get() };
    let storage = unsafe { env.ctx.storage.get() };
    let native_token = vp_host_fns::get_native_token(gas_meter, storage)?;
    let native_token_string = native_token.encode();
    let gas = env
        .memory
        .write_string(result_ptr, native_token_string)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    vp_host_fns::add_gas(gas_meter, gas)
}

/// Log a string from exposed to the wasm VM VP environment. The message will be
/// printed at the [`tracing::Level::INFO`]. This function is for development
/// only.
pub fn vp_log_string<MEM, DB, H, EVAL, CA>(
    env: &VpVmEnv<MEM, DB, H, EVAL, CA>,
    str_ptr: u64,
    str_len: u64,
) -> vp_host_fns::EnvResult<()>
where
    MEM: VmMemory,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    EVAL: VpEvaluator,
    CA: WasmCacheAccess,
{
    let (str, _gas) = env
        .memory
        .read_string(str_ptr, str_len as _)
        .map_err(|e| vp_host_fns::RuntimeError::MemoryError(Box::new(e)))?;
    tracing::info!("WASM Validity predicate log: {}", str);
    Ok(())
}

// Temp. workaround for <https://github.com/anoma/namada/issues/1831>
impl<'a, DB, H, CA> namada_core::ledger::ibc::IbcStorageContext
    for TxCtx<'a, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    type Error = TxRuntimeError;
    // type PrefixIter<'iter> = KeyValIterator<(String, Vec<u8>)>;
    type PrefixIter<'iter> = u64 where Self: 'iter;

    fn read(
        &self,
        key: &Key,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        let write_log = unsafe { self.write_log.get() };
        let (log_val, gas) = write_log.read(key);
        ibc_tx_charge_gas(self, gas)?;
        Ok(match log_val {
            Some(write_log::StorageModification::Write { ref value }) => {
                Some(value.clone())
            }
            Some(&write_log::StorageModification::Delete) => None,
            Some(write_log::StorageModification::InitAccount {
                ref vp_code_hash,
            }) => Some(vp_code_hash.to_vec()),
            Some(write_log::StorageModification::Temp { ref value }) => {
                Some(value.clone())
            }
            None => {
                // when not found in write log, try to read from the storage
                let storage = unsafe { self.storage.get() };
                let (value, gas) =
                    storage.read(key).map_err(TxRuntimeError::StorageError)?;
                ibc_tx_charge_gas(self, gas)?;
                value
            }
        })
    }

    fn has_key(&self, key: &Key) -> Result<bool, Self::Error> {
        // try to read from the write log first
        let write_log = unsafe { self.write_log.get() };
        let (log_val, gas) = write_log.read(key);
        ibc_tx_charge_gas(self, gas)?;
        Ok(match log_val {
            Some(&write_log::StorageModification::Write { .. }) => true,
            Some(&write_log::StorageModification::Delete) => false,
            Some(&write_log::StorageModification::InitAccount { .. }) => true,
            Some(&write_log::StorageModification::Temp { .. }) => true,
            None => {
                // when not found in write log, try to check the storage
                let storage = unsafe { self.storage.get() };
                let (present, gas) = storage
                    .has_key(key)
                    .map_err(TxRuntimeError::StorageError)?;
                ibc_tx_charge_gas(self, gas)?;
                present
            }
        })
    }

    fn write(
        &mut self,
        key: &Key,
        data: Vec<u8>,
    ) -> std::result::Result<(), Self::Error> {
        let write_log = unsafe { self.write_log.get() };
        let (gas, _size_diff) = write_log
            .write(key, data)
            .map_err(TxRuntimeError::StorageModificationError)?;
        ibc_tx_charge_gas(self, gas)
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>, Self::Error> {
        let write_log = unsafe { self.write_log.get() };
        let storage = unsafe { self.storage.get() };
        let (iter, gas) = storage::iter_prefix_post(write_log, storage, prefix);
        ibc_tx_charge_gas(self, gas)?;

        let iterators = unsafe { self.iterators.get() };
        Ok(iterators.insert(iter).id())
    }

    fn iter_next<'iter>(
        &'iter self,
        iter_id: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, Self::Error> {
        let write_log = unsafe { self.write_log.get() };
        let iterators = unsafe { self.iterators.get() };
        let iter_id = PrefixIteratorId::new(*iter_id);
        while let Some((key, val, iter_gas)) = iterators.next(iter_id) {
            let (log_val, log_gas) = write_log.read(
                &Key::parse(key.clone())
                    .map_err(TxRuntimeError::StorageDataError)?,
            );
            ibc_tx_charge_gas(self, iter_gas + log_gas)?;
            match log_val {
                Some(write_log::StorageModification::Write { ref value }) => {
                    return Ok(Some((key, value.clone())));
                }
                Some(&write_log::StorageModification::Delete) => {
                    // check the next because the key has already deleted
                    continue;
                }
                Some(&write_log::StorageModification::InitAccount {
                    ..
                }) => {
                    // a VP of a new account doesn't need to be iterated
                    continue;
                }
                Some(write_log::StorageModification::Temp { ref value }) => {
                    return Ok(Some((key, value.clone())));
                }
                None => {
                    return Ok(Some((key, val)));
                }
            }
        }
        Ok(None)
    }

    fn delete(&mut self, key: &Key) -> std::result::Result<(), Self::Error> {
        if key.is_validity_predicate().is_some() {
            return Err(TxRuntimeError::CannotDeleteVp);
        }

        let write_log = unsafe { self.write_log.get() };
        let (gas, _size_diff) = write_log
            .delete(key)
            .map_err(TxRuntimeError::StorageModificationError)?;
        ibc_tx_charge_gas(self, gas)
    }

    fn emit_ibc_event(
        &mut self,
        event: IbcEvent,
    ) -> std::result::Result<(), Self::Error> {
        let write_log = unsafe { self.write_log.get() };
        let gas = write_log.emit_ibc_event(event);
        ibc_tx_charge_gas(self, gas)
    }

    fn get_ibc_event(
        &self,
        event_type: impl AsRef<str>,
    ) -> Result<Option<IbcEvent>, Self::Error> {
        let write_log = unsafe { self.write_log.get() };
        Ok(write_log
            .get_ibc_events()
            .iter()
            .find(|event| event.event_type == event_type.as_ref())
            .cloned())
    }

    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: namada_core::types::token::DenominatedAmount,
    ) -> std::result::Result<(), Self::Error> {
        use namada_core::types::token;

        if amount.amount != token::Amount::default() && src != dest {
            let src_key = token::balance_key(token, src);
            let dest_key = token::balance_key(token, dest);
            let src_bal: Option<token::Amount> =
                ibc_read_borsh(self, &src_key)?;
            let mut src_bal = src_bal.unwrap_or_else(|| {
                self.log_string(format!("src {} has no balance", src_key));
                unreachable!()
            });
            src_bal.spend(&amount.amount);
            let mut dest_bal: token::Amount =
                ibc_read_borsh(self, &dest_key)?.unwrap_or_default();
            dest_bal.receive(&amount.amount);
            ibc_write_borsh(self, &src_key, &src_bal)?;
            ibc_write_borsh(self, &dest_key, &dest_bal)?;
        }
        Ok(())
    }

    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: namada_core::types::token::DenominatedAmount,
    ) -> Result<(), Self::Error> {
        use namada_core::types::token;

        let target_key = token::balance_key(token, target);
        let mut target_bal: token::Amount =
            ibc_read_borsh(self, &target_key)?.unwrap_or_default();
        target_bal.receive(&amount.amount);

        let minted_key = token::minted_balance_key(token);
        let mut minted_bal: token::Amount =
            ibc_read_borsh(self, &minted_key)?.unwrap_or_default();
        minted_bal.receive(&amount.amount);

        ibc_write_borsh(self, &target_key, &target_bal)?;
        ibc_write_borsh(self, &minted_key, &minted_bal)?;

        let minter_key = token::minter_key(token);
        ibc_write_borsh(
            self,
            &minter_key,
            &Address::Internal(address::InternalAddress::Ibc),
        )?;

        Ok(())
    }

    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: namada_core::types::token::DenominatedAmount,
    ) -> Result<(), Self::Error> {
        use namada_core::types::token;

        let target_key = token::balance_key(token, target);
        let mut target_bal: token::Amount =
            ibc_read_borsh(self, &target_key)?.unwrap_or_default();
        target_bal.spend(&amount.amount);

        // burn the minted amount
        let minted_key = token::minted_balance_key(token);
        let mut minted_bal: token::Amount =
            ibc_read_borsh(self, &minted_key)?.unwrap_or_default();
        minted_bal.spend(&amount.amount);

        ibc_write_borsh(self, &target_key, &target_bal)?;
        ibc_write_borsh(self, &minted_key, &minted_bal)?;

        Ok(())
    }

    fn get_height(&self) -> std::result::Result<BlockHeight, Self::Error> {
        let storage = unsafe { self.storage.get() };
        let (height, gas) = storage.get_block_height();
        ibc_tx_charge_gas(self, gas)?;
        Ok(height)
    }

    fn get_header(
        &self,
        height: BlockHeight,
    ) -> std::result::Result<
        Option<namada_core::types::storage::Header>,
        Self::Error,
    > {
        let storage = unsafe { self.storage.get() };
        let (header, gas) = storage
            .get_block_header(Some(height))
            .map_err(TxRuntimeError::StorageError)?;
        ibc_tx_charge_gas(self, gas)?;
        Ok(header)
    }

    fn log_string(&self, message: String) {
        tracing::info!("IBC host env log: {}", message);
    }
}

/// Add a gas cost incured in a transaction
// Temp helper.
fn ibc_tx_charge_gas<'a, DB, H, CA>(
    ctx: &TxCtx<'a, DB, H, CA>,
    used_gas: u64,
) -> TxResult<()>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let gas_meter = unsafe { ctx.gas_meter.get() };
    // if we run out of gas, we need to stop the execution
    let result = gas_meter
        .consume(used_gas)
        .map_err(TxRuntimeError::OutOfGas);
    if let Err(err) = &result {
        tracing::info!(
            "Stopping transaction execution because of gas error: {}",
            err
        );
    }
    result
}

/// Read borsh encoded val by key.
// Temp helper for ibc tx workaround.
fn ibc_read_borsh<'a, T, DB, H, CA>(
    ctx: &TxCtx<'a, DB, H, CA>,
    key: &Key,
) -> TxResult<Option<T>>
where
    T: BorshDeserialize,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let bytes = namada_core::ledger::ibc::IbcStorageContext::read(ctx, key)?;
    match bytes {
        Some(bytes) => {
            let val = T::try_from_slice(&bytes)
                .map_err(TxRuntimeError::EncodingError)?;
            Ok(Some(val))
        }
        None => Ok(None),
    }
}

/// Write borsh encoded val by key.
// Temp helper for ibc tx workaround.
fn ibc_write_borsh<'a, T, DB, H, CA>(
    ctx: &mut TxCtx<'a, DB, H, CA>,
    key: &Key,
    val: &T,
) -> TxResult<()>
where
    T: BorshSerialize,
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    let bytes = val.try_to_vec().map_err(TxRuntimeError::EncodingError)?;
    namada_core::ledger::ibc::IbcStorageContext::write(ctx, key, bytes)?;
    Ok(())
}

// Temp. workaround for <https://github.com/anoma/namada/issues/1831>
impl<'a, DB, H, CA> namada_core::ledger::ibc::IbcCommonContext
    for TxCtx<'a, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
}

/// A helper module for testing
#[cfg(feature = "testing")]
pub mod testing {
    use std::collections::BTreeSet;

    use super::*;
    use crate::ledger::storage::traits::StorageHasher;
    use crate::ledger::storage::{self};
    use crate::vm::memory::testing::NativeMemory;

    /// Setup a transaction environment
    #[allow(clippy::too_many_arguments)]
    pub fn tx_env<DB, H, CA>(
        storage: &Storage<DB, H>,
        write_log: &mut WriteLog,
        iterators: &mut PrefixIterators<'static, DB>,
        verifiers: &mut BTreeSet<Address>,
        gas_meter: &mut TxGasMeter,
        tx: &Tx,
        tx_index: &TxIndex,
        result_buffer: &mut Option<Vec<u8>>,
        #[cfg(feature = "wasm-runtime")] vp_wasm_cache: &mut VpCache<CA>,
        #[cfg(feature = "wasm-runtime")] tx_wasm_cache: &mut TxCache<CA>,
    ) -> TxVmEnv<'static, NativeMemory, DB, H, CA>
    where
        DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
        H: StorageHasher,
        CA: WasmCacheAccess,
    {
        TxVmEnv::new(
            NativeMemory,
            storage,
            write_log,
            iterators,
            gas_meter,
            tx,
            tx_index,
            verifiers,
            result_buffer,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache,
            #[cfg(feature = "wasm-runtime")]
            tx_wasm_cache,
        )
    }

    /// Setup a validity predicate environment
    #[allow(clippy::too_many_arguments)]
    pub fn vp_env<DB, H, EVAL, CA>(
        address: &Address,
        storage: &Storage<DB, H>,
        write_log: &WriteLog,
        iterators: &mut PrefixIterators<'static, DB>,
        gas_meter: &mut VpGasMeter,
        tx: &Tx,
        tx_index: &TxIndex,
        verifiers: &BTreeSet<Address>,
        result_buffer: &mut Option<Vec<u8>>,
        keys_changed: &BTreeSet<Key>,
        eval_runner: &EVAL,
        #[cfg(feature = "wasm-runtime")] vp_wasm_cache: &mut VpCache<CA>,
    ) -> VpVmEnv<'static, NativeMemory, DB, H, EVAL, CA>
    where
        DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
        H: StorageHasher,
        EVAL: VpEvaluator,
        CA: WasmCacheAccess,
    {
        VpVmEnv::new(
            NativeMemory,
            address,
            storage,
            write_log,
            gas_meter,
            tx,
            tx_index,
            iterators,
            verifiers,
            result_buffer,
            keys_changed,
            eval_runner,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache,
        )
    }
}
