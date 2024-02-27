//! Wasm runners

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::marker::PhantomData;

use borsh::BorshDeserialize;
use namada_core::validity_predicate::VpSentinel;
use namada_gas::{GasMetering, TxGasMeter, WASM_MEMORY_PAGE_GAS};
use namada_state::write_log::StorageModification;
use namada_state::{DBIter, State, StateRead, StorageHasher, DB};
use namada_tx::data::TxSentinel;
use namada_tx::{Commitment, Section, Tx};
use parity_wasm::elements;
use thiserror::Error;
use wasmer::{BaseTunables, Module, Store};

use super::memory::{Limit, WasmMemory};
use super::TxCache;
use crate::address::Address;
use crate::hash::{Error as TxHashError, Hash};
use crate::internal::HostEnvResult;
use crate::ledger::gas::VpGasMeter;
use crate::storage::{Key, TxIndex};
use crate::vm::host_env::{TxVmEnv, VpCtx, VpEvaluator, VpVmEnv};
use crate::vm::prefix_iter::PrefixIterators;
use crate::vm::types::VpInput;
use crate::vm::wasm::host_env::{tx_imports, vp_imports};
use crate::vm::wasm::{memory, Cache, CacheName, VpCache};
use crate::vm::{
    validate_untrusted_wasm, WasmCacheAccess, WasmValidationError,
};

const TX_ENTRYPOINT: &str = "_apply_tx";
const VP_ENTRYPOINT: &str = "_validate_tx";
const WASM_STACK_LIMIT: u32 = u16::MAX as u32;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Missing tx section: {0}")]
    MissingSection(String),
    #[error("Memory error: {0}")]
    MemoryError(memory::Error),
    #[error("Unable to inject stack limiter")]
    StackLimiterInjection,
    #[error("Wasm deserialization error: {0}")]
    DeserializationError(elements::Error),
    #[error("Wasm serialization error: {0}")]
    SerializationError(elements::Error),
    #[error("Unable to inject gas meter")]
    GasMeterInjection,
    #[error("Wasm compilation error: {0}")]
    CompileError(wasmer::CompileError),
    #[error("Missing wasm memory export, failed with: {0}")]
    MissingModuleMemory(wasmer::ExportError),
    #[error("Missing wasm entrypoint: {0}")]
    MissingModuleEntrypoint(wasmer::ExportError),
    #[error("Failed running wasm with: {0}")]
    RuntimeError(wasmer::RuntimeError),
    #[error("Failed instantiating wasm module with: {0}")]
    // Boxed cause it's 128b
    InstantiationError(Box<wasmer::InstantiationError>),
    #[error(
        "Unexpected module entrypoint interface {entrypoint}, failed with: \
         {error}"
    )]
    UnexpectedModuleEntrypointInterface {
        entrypoint: &'static str,
        error: wasmer::RuntimeError,
    },
    #[error("Wasm validation error: {0}")]
    ValidationError(WasmValidationError),
    #[error("Wasm code hash error: {0}")]
    CodeHash(TxHashError),
    #[error("Unable to load wasm code: {0}")]
    LoadWasmCode(String),
    #[error("Unable to find compiled wasm code")]
    NoCompiledWasmCode,
    #[error("Gas error: {0}")]
    GasError(String),
    #[error("Failed type conversion: {0}")]
    ConversionError(String),
    #[error("Invalid transaction signature")]
    InvalidTxSignature,
}

/// Result for functions that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// Execute a transaction code. Returns the set verifiers addresses requested by
/// the transaction.
#[allow(clippy::too_many_arguments)]
pub fn tx<S, CA>(
    state: &mut S,
    gas_meter: &RefCell<TxGasMeter>,
    tx_index: &TxIndex,
    tx: &Tx,
    vp_wasm_cache: &mut VpCache<CA>,
    tx_wasm_cache: &mut TxCache<CA>,
) -> Result<BTreeSet<Address>>
where
    S: StateRead + State,
    CA: 'static + WasmCacheAccess,
{
    let tx_code = tx
        .get_section(tx.code_sechash())
        .and_then(|x| Section::code_sec(x.as_ref()))
        .ok_or(Error::MissingSection(tx.code_sechash().to_string()))?;

    // If the transaction code has a tag, ensure that the tag hash equals the
    // transaction code's hash.
    if let Some(tag) = &tx_code.tag {
        // Get the WASM code hash corresponding to the tag from storage
        let hash_key = Key::wasm_hash(tag);
        let hash_value = match state.read_bytes(&hash_key).map_err(|e| {
            Error::LoadWasmCode(format!(
                "Read wasm code hash failed from storage: key {}, error {}",
                hash_key, e
            ))
        })? {
            Some(v) => Hash::try_from_slice(&v)
                .map_err(|e| Error::ConversionError(e.to_string()))?,
            None => {
                return Err(Error::LoadWasmCode(format!(
                    "No wasm code hash in storage: key {}",
                    hash_key
                )));
            }
        };
        // Ensure that the queried code hash equals the transaction's code hash
        let tx_code_hash = tx_code.code.hash();
        if tx_code_hash != hash_value {
            return Err(Error::LoadWasmCode(format!(
                "Transaction code hash does not correspond to tag: tx hash \
                 {}, tag {}, tag hash {}",
                tx_code_hash, tag, hash_value,
            )));
        }
    }

    let (module, store) =
        fetch_or_compile(tx_wasm_cache, &tx_code.code, state, gas_meter)?;

    let mut iterators: PrefixIterators<'_, <S as StateRead>::D> =
        PrefixIterators::default();
    let mut verifiers = BTreeSet::new();
    let mut result_buffer: Option<Vec<u8>> = None;

    let sentinel = RefCell::new(TxSentinel::default());
    let (write_log, in_mem, db) = state.split_borrow();
    let env = TxVmEnv::new(
        WasmMemory::default(),
        write_log,
        in_mem,
        db,
        &mut iterators,
        gas_meter,
        &sentinel,
        tx,
        tx_index,
        &mut verifiers,
        &mut result_buffer,
        vp_wasm_cache,
        tx_wasm_cache,
    );

    let initial_memory =
        memory::prepare_tx_memory(&store).map_err(Error::MemoryError)?;
    let imports = tx_imports(&store, initial_memory, env);

    // Instantiate the wasm module
    let instance = wasmer::Instance::new(&module, &imports)
        .map_err(|e| Error::InstantiationError(Box::new(e)))?;

    // We need to write the inputs in the memory exported from the wasm
    // module
    let memory = instance
        .exports
        .get_memory("memory")
        .map_err(Error::MissingModuleMemory)?;
    let memory::TxCallInput {
        tx_data_ptr,
        tx_data_len,
    } = memory::write_tx_inputs(memory, tx).map_err(Error::MemoryError)?;
    // Get the module's entrypoint to be called
    let apply_tx = instance
        .exports
        .get_function(TX_ENTRYPOINT)
        .map_err(Error::MissingModuleEntrypoint)?
        .native::<(u64, u64), ()>()
        .map_err(|error| Error::UnexpectedModuleEntrypointInterface {
            entrypoint: TX_ENTRYPOINT,
            error,
        })?;
    apply_tx.call(tx_data_ptr, tx_data_len).map_err(|err| {
        tracing::debug!("Tx WASM failed with {}", err);
        match *sentinel.borrow() {
            TxSentinel::None => Error::RuntimeError(err),
            TxSentinel::OutOfGas => Error::GasError(err.to_string()),
            TxSentinel::InvalidCommitment => {
                Error::MissingSection(err.to_string())
            }
        }
    })?;

    Ok(verifiers)
}

/// Execute a validity predicate code. Returns whether the validity
/// predicate accepted storage modifications performed by the transaction
/// that triggered the execution.
#[allow(clippy::too_many_arguments)]
pub fn vp<S, CA>(
    vp_code_hash: Hash,
    tx: &Tx,
    tx_index: &TxIndex,
    address: &Address,
    state: &S,
    gas_meter: &RefCell<VpGasMeter>,
    keys_changed: &BTreeSet<Key>,
    verifiers: &BTreeSet<Address>,
    mut vp_wasm_cache: VpCache<CA>,
) -> Result<bool>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    // Compile the wasm module
    let (module, store) = fetch_or_compile(
        &mut vp_wasm_cache,
        &Commitment::Hash(vp_code_hash),
        state,
        gas_meter,
    )?;

    let mut iterators: PrefixIterators<'_, <S as StateRead>::D> =
        PrefixIterators::default();
    let mut result_buffer: Option<Vec<u8>> = None;
    let eval_runner =
        VpEvalWasm::<<S as StateRead>::D, <S as StateRead>::H, CA> {
            db: PhantomData,
            hasher: PhantomData,
            cache_access: PhantomData,
        };
    let sentinel = RefCell::new(VpSentinel::default());
    let env = VpVmEnv::new(
        WasmMemory::default(),
        address,
        state.write_log(),
        state.in_mem(),
        state.db(),
        gas_meter,
        &sentinel,
        tx,
        tx_index,
        &mut iterators,
        verifiers,
        &mut result_buffer,
        keys_changed,
        &eval_runner,
        &mut vp_wasm_cache,
    );

    let initial_memory =
        memory::prepare_vp_memory(&store).map_err(Error::MemoryError)?;
    let imports = vp_imports(&store, initial_memory, env);

    match run_vp(
        module,
        imports,
        &vp_code_hash,
        tx,
        address,
        keys_changed,
        verifiers,
    ) {
        Ok(accept) => {
            if sentinel.borrow().is_invalid_signature() {
                if accept {
                    // This is unexpected, if the signature is invalid the vp
                    // should have rejected the tx. Something must be wrong with
                    // the VP logic and we take the signature verification
                    // result as the reference. In this case we override the vp
                    // result and log the issue
                    tracing::warn!(
                        "VP of {address} accepted the transaction but \
                         signaled that the signature was invalid. Overriding \
                         the vp result to reject the transaction..."
                    );
                }
                Err(Error::InvalidTxSignature)
            } else {
                Ok(accept)
            }
        }
        Err(err) => {
            if sentinel.borrow().is_out_of_gas() {
                Err(Error::GasError(err.to_string()))
            } else {
                Err(err)
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_vp(
    module: wasmer::Module,
    vp_imports: wasmer::ImportObject,
    _vp_code_hash: &Hash,
    input_data: &Tx,
    address: &Address,
    keys_changed: &BTreeSet<Key>,
    verifiers: &BTreeSet<Address>,
) -> Result<bool> {
    let input: VpInput = VpInput {
        addr: address,
        data: input_data,
        keys_changed,
        verifiers,
    };

    // Instantiate the wasm module
    let instance = wasmer::Instance::new(&module, &vp_imports)
        .map_err(|e| Error::InstantiationError(Box::new(e)))?;

    // We need to write the inputs in the memory exported from the wasm
    // module
    let memory = instance
        .exports
        .get_memory("memory")
        .map_err(Error::MissingModuleMemory)?;
    let memory::VpCallInput {
        addr_ptr,
        addr_len,
        data_ptr,
        data_len,
        keys_changed_ptr,
        keys_changed_len,
        verifiers_ptr,
        verifiers_len,
    } = memory::write_vp_inputs(memory, input).map_err(Error::MemoryError)?;

    // Get the module's entrypoint to be called
    let validate_tx = instance
        .exports
        .get_function(VP_ENTRYPOINT)
        .map_err(Error::MissingModuleEntrypoint)?
        .native::<(u64, u64, u64, u64, u64, u64, u64, u64), u64>()
        .map_err(|error| Error::UnexpectedModuleEntrypointInterface {
            entrypoint: VP_ENTRYPOINT,
            error,
        })?;
    let is_valid = validate_tx
        .call(
            addr_ptr,
            addr_len,
            data_ptr,
            data_len,
            keys_changed_ptr,
            keys_changed_len,
            verifiers_ptr,
            verifiers_len,
        )
        .map_err(Error::RuntimeError)?;
    tracing::debug!("is_valid {}", is_valid);
    Ok(is_valid == 1)
}

/// Validity predicate wasm evaluator for `eval` host function calls.
#[derive(Default, Debug)]
pub struct VpEvalWasm<D, H, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    /// Phantom type for DB
    pub db: PhantomData<*const D>,
    /// Phantom type for hasher
    pub hasher: PhantomData<*const H>,
    /// Phantom type for WASM compilation cache access
    pub cache_access: PhantomData<*const CA>,
}

impl<D, H, CA> VpEvaluator for VpEvalWasm<D, H, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    type CA = CA;
    type Db = D;
    type Eval = Self;
    type H = H;

    fn eval(
        &self,
        ctx: VpCtx<'static, D, H, Self, CA>,
        vp_code_hash: Hash,
        input_data: Tx,
    ) -> HostEnvResult {
        match self.eval_native_result(ctx, vp_code_hash, input_data) {
            Ok(ok) => HostEnvResult::from(ok),
            Err(err) => {
                tracing::warn!("VP eval error {}", err);
                HostEnvResult::Fail
            }
        }
    }
}

impl<D, H, CA> VpEvalWasm<D, H, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    /// Evaluate the given VP.
    pub fn eval_native_result(
        &self,
        ctx: VpCtx<'static, D, H, Self, CA>,
        vp_code_hash: Hash,
        input_data: Tx,
    ) -> Result<bool> {
        let address = unsafe { ctx.address.get() };
        let keys_changed = unsafe { ctx.keys_changed.get() };
        let verifiers = unsafe { ctx.verifiers.get() };
        let vp_wasm_cache = unsafe { ctx.vp_wasm_cache.get() };
        let gas_meter = unsafe { ctx.gas_meter.get() };

        // Compile the wasm module
        let (module, store) = fetch_or_compile(
            vp_wasm_cache,
            &Commitment::Hash(vp_code_hash),
            &ctx.state(),
            gas_meter,
        )?;

        let initial_memory =
            memory::prepare_vp_memory(&store).map_err(Error::MemoryError)?;

        let env = VpVmEnv {
            memory: WasmMemory::default(),
            ctx,
        };
        let imports = vp_imports(&store, initial_memory, env);

        run_vp(
            module,
            imports,
            &vp_code_hash,
            &input_data,
            address,
            keys_changed,
            verifiers,
        )
    }
}

/// Prepare a wasm store for untrusted code.
pub fn untrusted_wasm_store(limit: Limit<BaseTunables>) -> wasmer::Store {
    // Use Singlepass compiler with the default settings
    let compiler = wasmer_compiler_singlepass::Singlepass::default();
    wasmer::Store::new_with_tunables(
        &wasmer_engine_universal::Universal::new(compiler).engine(),
        limit,
    )
}

/// Inject gas counter and stack-height limiter into the given wasm code
pub fn prepare_wasm_code<T: AsRef<[u8]>>(code: T) -> Result<Vec<u8>> {
    let module: elements::Module = elements::deserialize_buffer(code.as_ref())
        .map_err(Error::DeserializationError)?;
    let module = wasm_instrument::gas_metering::inject(
        module,
        wasm_instrument::gas_metering::host_function::Injector::new(
            "env", "gas",
        ),
        &get_gas_rules(),
    )
    .map_err(|_original_module| Error::GasMeterInjection)?;
    let module =
        wasm_instrument::inject_stack_limiter(module, WASM_STACK_LIMIT)
            .map_err(|_original_module| Error::StackLimiterInjection)?;
    elements::serialize(module).map_err(Error::SerializationError)
}

// Fetch or compile a WASM code from the cache or storage. Account for the
// loading and code compilation gas costs.
fn fetch_or_compile<S, CN, CA>(
    wasm_cache: &mut Cache<CN, CA>,
    code_or_hash: &Commitment,
    state: &S,
    gas_meter: &RefCell<impl GasMetering>,
) -> Result<(Module, Store)>
where
    S: StateRead,
    CN: 'static + CacheName,
    CA: 'static + WasmCacheAccess,
{
    match code_or_hash {
        Commitment::Hash(code_hash) => {
            let (module, store, tx_len) = match wasm_cache.fetch(code_hash)? {
                Some((module, store)) => {
                    // Gas accounting even if the compiled module is in cache
                    let key = Key::wasm_code_len(code_hash);
                    let tx_len = match state.write_log().read(&key).0 {
                        Some(StorageModification::Write { value }) => {
                            u64::try_from_slice(value).map_err(|e| {
                                Error::ConversionError(e.to_string())
                            })
                        }
                        _ => match state
                            .db_read(&key)
                            .map_err(|e| {
                                Error::LoadWasmCode(format!(
                                    "Read wasm code length failed from \
                                     storage: key {}, error {}",
                                    key, e
                                ))
                            })?
                            .0
                        {
                            Some(v) => u64::try_from_slice(&v).map_err(|e| {
                                Error::ConversionError(e.to_string())
                            }),
                            None => Err(Error::LoadWasmCode(format!(
                                "No wasm code length in storage: key {}",
                                key
                            ))),
                        },
                    }?;

                    (module, store, tx_len)
                }
                None => {
                    let key = Key::wasm_code(code_hash);
                    let code = match state.write_log().read(&key).0 {
                        Some(StorageModification::Write { value }) => {
                            value.clone()
                        }
                        _ => match state
                            .db_read(&key)
                            .map_err(|e| {
                                Error::LoadWasmCode(format!(
                                    "Read wasm code failed from storage: key \
                                     {}, error {}",
                                    key, e
                                ))
                            })?
                            .0
                        {
                            Some(v) => v,
                            None => {
                                return Err(Error::LoadWasmCode(format!(
                                    "No wasm code in storage: key {}",
                                    key
                                )));
                            }
                        },
                    };
                    let tx_len = u64::try_from(code.len())
                        .map_err(|e| Error::ConversionError(e.to_string()))?;

                    match wasm_cache.compile_or_fetch(code)? {
                        Some((module, store)) => (module, store, tx_len),
                        None => return Err(Error::NoCompiledWasmCode),
                    }
                }
            };

            gas_meter
                .borrow_mut()
                .add_wasm_load_from_storage_gas(tx_len)
                .map_err(|e| Error::GasError(e.to_string()))?;
            gas_meter
                .borrow_mut()
                .add_compiling_gas(tx_len)
                .map_err(|e| Error::GasError(e.to_string()))?;
            Ok((module, store))
        }
        Commitment::Id(code) => {
            let tx_len = code.len() as u64;
            gas_meter
                .borrow_mut()
                .add_wasm_validation_gas(tx_len)
                .map_err(|e| Error::GasError(e.to_string()))?;
            validate_untrusted_wasm(code).map_err(Error::ValidationError)?;

            gas_meter
                .borrow_mut()
                .add_compiling_gas(tx_len)
                .map_err(|e| Error::GasError(e.to_string()))?;
            match wasm_cache.compile_or_fetch(code)? {
                Some((module, store)) => Ok((module, store)),
                None => Err(Error::NoCompiledWasmCode),
            }
        }
    }
}

/// Get the gas rules used to meter wasm operations
fn get_gas_rules() -> wasm_instrument::gas_metering::ConstantCostRules {
    // NOTE: costs set to 0 don't actually trigger the injection of a call to
    // the gas host function (no useless instructions are injected)
    let instruction_cost = 0;
    let memory_grow_cost = WASM_MEMORY_PAGE_GAS;
    let call_per_local_cost = 0;
    wasm_instrument::gas_metering::ConstantCostRules::new(
        instruction_cost,
        memory_grow_cost,
        call_per_local_cost,
    )
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdErrorTrait;

    use borsh_ext::BorshSerializeExt;
    use itertools::Either;
    use namada_state::StorageWrite;
    use namada_test_utils::TestWasms;
    use namada_tx::data::TxType;
    use namada_tx::{Code, Data};
    use test_log::test;
    use wasmer_vm::TrapCode;

    use super::*;
    use crate::state::testing::TestState;
    use crate::tx::data::eval_vp::EvalVp;
    use crate::vm::host_env::TxRuntimeError;
    use crate::vm::wasm;

    const TX_GAS_LIMIT: u64 = 10_000_000_000;

    /// Test that we sanitize accesses to invalid addresses in wasm memory.
    #[test]
    fn test_tx_sanitize_invalid_addrs() {
        let tx_code = wasmer::wat2wasm(
            r#"
            (module
                (import "env" "namada_tx_read" (func (param i64 i64) (result i64)))
                (func (param i64 i64)
                    i64.const 18446744073709551615
                    i64.const 1
                    (call 0)
                    drop
                )
                (memory 16)
                (export "memory" (memory 0))
                (export "_apply_tx" (func 1))
            )
            "#
            .as_bytes(),
        )
        .expect("unexpected error converting wat2wasm")
        .into_owned();

        const PANIC_MSG: &str =
            "Test should have failed with a wasm runtime memory error";

        let error = execute_tx_with_code(tx_code).expect_err(PANIC_MSG);
        assert!(
            matches!(
                assert_rt_mem_error(&error, PANIC_MSG),
                memory::Error::OverflowingOffset(18446744073709551615, 1),
            ),
            "{PANIC_MSG}"
        );
    }

    /// Extract a wasm runtime memory error from some [`Error`].
    fn assert_rt_mem_error<'err>(
        error: &'err Error,
        assert_msg: &str,
    ) -> &'err memory::Error {
        let Error::RuntimeError(rt_error) = error else {
            panic!("{assert_msg}: {error}");
        };
        let source_err =
            rt_error.source().expect("No runtime error source found");
        let downcasted_tx_rt_err: &TxRuntimeError = source_err
            .downcast_ref()
            .unwrap_or_else(|| panic!("{assert_msg}: {source_err}"));
        let TxRuntimeError::MemoryError(tx_mem_err) = downcasted_tx_rt_err
        else {
            panic!("{assert_msg}: {downcasted_tx_rt_err}");
        };
        tx_mem_err
            .downcast_ref()
            .unwrap_or_else(|| panic!("{assert_msg}: {tx_mem_err}"))
    }

    /// Test that when a transaction wasm goes over the stack-height limit, the
    /// execution is aborted.
    #[test]
    // NB: Disabled on aarch64 macOS since a fix for
    // https://github.com/wasmerio/wasmer/issues/4072
    // reduced the available stack space on mac
    #[cfg_attr(all(target_arch = "aarch64", target_os = "macos"), ignore)]
    fn test_tx_stack_limiter() {
        // Because each call into `$loop` inside the wasm consumes 5 stack
        // heights except for the terminal call, this should hit the stack
        // limit.
        let loops = WASM_STACK_LIMIT / 5 - 1;

        let error = loop_in_tx_wasm(loops).expect_err(&format!(
            "Expecting runtime error \"unreachable\" caused by stack-height \
             overflow, loops {}. Got",
            loops,
        ));
        assert_stack_overflow(&error);

        // one less loop shouldn't go over the limit
        let result = loop_in_tx_wasm(loops - 1);
        assert!(result.is_ok(), "Expected success. Got {:?}", result);
    }

    /// Test that when a VP wasm goes over the stack-height limit, the execution
    /// is aborted.
    #[test]
    // NB: Disabled on aarch64 macOS since a fix for
    // https://github.com/wasmerio/wasmer/issues/4072
    // reduced the available stack space on mac
    #[cfg_attr(all(target_arch = "aarch64", target_os = "macos"), ignore)]
    fn test_vp_stack_limiter() {
        // Because each call into `$loop` inside the wasm consumes 5 stack
        // heights except for the terminal call, this should hit the stack
        // limit.
        let loops = WASM_STACK_LIMIT / 5 - 1;

        let error = loop_in_vp_wasm(loops).expect_err(
            "Expecting runtime error caused by stack-height overflow. Got",
        );
        assert_stack_overflow(&error);

        // one less loop shouldn't go over the limit
        let result = loop_in_vp_wasm(loops - 1);
        assert!(result.is_ok(), "Expected success. Got {:?}", result);
    }

    /// Test that when a transaction wasm goes over the memory limit inside the
    /// wasm execution, the execution is aborted.
    #[test]
    fn test_tx_memory_limiter_in_guest() {
        let mut state = TestState::default();
        let gas_meter =
            RefCell::new(TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()));
        let tx_index = TxIndex::default();

        // This code will allocate memory of the given size
        let tx_code = TestWasms::TxMemoryLimit.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&tx_code);
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let code_len = (tx_code.len() as u64).serialize_to_vec();
        state.write_log_mut().write(&key, tx_code.clone()).unwrap();
        state.write_log_mut().write(&len_key, code_len).unwrap();

        // Assuming 200 pages, 12.8 MiB limit
        assert_eq!(memory::TX_MEMORY_MAX_PAGES, 200);

        // Allocating `2^23` (8 MiB) should be below the memory limit and
        // shouldn't fail
        let tx_data = 2_usize.pow(23).serialize_to_vec();
        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::cache();
        let (mut tx_cache, _) =
            wasm::compilation_cache::common::testing::cache();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::new(tx_code.clone(), None));
        outer_tx.set_data(Data::new(tx_data));
        let result = tx(
            &mut state,
            &gas_meter,
            &tx_index,
            &outer_tx,
            &mut vp_cache,
            &mut tx_cache,
        );
        assert!(result.is_ok(), "Expected success, got {:?}", result);

        // Allocating `2^24` (16 MiB) should be above the memory limit and
        // should fail
        let tx_data = 2_usize.pow(24).serialize_to_vec();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::new(tx_code, None));
        outer_tx.set_data(Data::new(tx_data));
        let error = tx(
            &mut state,
            &gas_meter,
            &tx_index,
            &outer_tx,
            &mut vp_cache,
            &mut tx_cache,
        )
        .expect_err("Expected to run out of memory");

        assert_stack_overflow(&error);
    }

    /// Test that when a validity predicate wasm goes over the memory limit
    /// inside the wasm execution when calling `eval` host function, the `eval`
    /// fails and hence returns `false`.
    #[test]
    fn test_vp_memory_limiter_in_guest_calling_eval() {
        let mut state = TestState::default();
        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();
        let tx_index = TxIndex::default();

        // This code will call `eval` with the other VP below
        let vp_eval = TestWasms::VpEval.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&vp_eval);
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let code_len = (vp_eval.len() as u64).serialize_to_vec();
        state.write_bytes(&key, vp_eval).unwrap();
        state.write_bytes(&len_key, code_len).unwrap();
        // This code will allocate memory of the given size
        let vp_memory_limit = TestWasms::VpMemoryLimit.read_bytes();
        // store the wasm code
        let limit_code_hash = Hash::sha256(&vp_memory_limit);
        let key = Key::wasm_code(&limit_code_hash);
        let len_key = Key::wasm_code_len(&limit_code_hash);
        let code_len = (vp_memory_limit.len() as u64).serialize_to_vec();
        state.write_bytes(&key, vp_memory_limit).unwrap();
        state.write_bytes(&len_key, code_len).unwrap();

        // Assuming 200 pages, 12.8 MiB limit
        assert_eq!(memory::VP_MEMORY_MAX_PAGES, 200);

        // Allocating `2^23` (8 MiB) should be below the memory limit and
        // shouldn't fail
        let input = 2_usize.pow(23).serialize_to_vec();

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(vec![], None).add_serialized_data(input);

        let eval_vp = EvalVp {
            vp_code_hash: limit_code_hash,
            input: tx,
        };

        let mut outer_tx = Tx::new(state.in_mem().chain_id.clone(), None);
        outer_tx.add_code(vec![], None).add_data(eval_vp);

        let (vp_cache, _) = wasm::compilation_cache::common::testing::cache();
        // When the `eval`ed VP doesn't run out of memory, it should return
        // `true`
        let passed = vp(
            code_hash,
            &outer_tx,
            &tx_index,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache.clone(),
        )
        .unwrap();
        assert!(passed);

        // Allocating `2^24` (16 MiB) should be above the memory limit and
        // should fail
        let input = 2_usize.pow(24).serialize_to_vec();
        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(vec![], None).add_data(input);

        let eval_vp = EvalVp {
            vp_code_hash: limit_code_hash,
            input: tx,
        };

        let mut outer_tx = Tx::new(state.in_mem().chain_id.clone(), None);
        outer_tx.add_code(vec![], None).add_data(eval_vp);

        // When the `eval`ed VP runs out of memory, its result should be
        // `false`, hence we should also get back `false` from the VP that
        // called `eval`.
        let passed = vp(
            code_hash,
            &outer_tx,
            &tx_index,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache,
        )
        .unwrap();

        assert!(!passed);
    }

    /// Test that when a validity predicate wasm goes over the memory limit
    /// inside the wasm execution, the execution is aborted.
    #[test]
    fn test_vp_memory_limiter_in_guest() {
        let mut state = TestState::default();
        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();
        let tx_index = TxIndex::default();

        // This code will allocate memory of the given size
        let vp_code = TestWasms::VpMemoryLimit.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&vp_code);
        let code_len = (vp_code.len() as u64).serialize_to_vec();
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        state.write_bytes(&key, vp_code).unwrap();
        state.write_bytes(&len_key, code_len).unwrap();

        // Assuming 200 pages, 12.8 MiB limit
        assert_eq!(memory::VP_MEMORY_MAX_PAGES, 200);

        // Allocating `2^23` (8 MiB) should be below the memory limit and
        // shouldn't fail
        let tx_data = 2_usize.pow(23).serialize_to_vec();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_data(Data::new(tx_data));
        outer_tx.set_code(Code::new(vec![], None));
        let (vp_cache, _) = wasm::compilation_cache::common::testing::cache();
        let result = vp(
            code_hash,
            &outer_tx,
            &tx_index,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache.clone(),
        );
        assert!(result.is_ok(), "Expected success, got {:?}", result);

        // Allocating `2^24` (16 MiB) should be above the memory limit and
        // should fail
        let tx_data = 2_usize.pow(24).serialize_to_vec();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_data(Data::new(tx_data));
        let error = vp(
            code_hash,
            &outer_tx,
            &tx_index,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache,
        )
        .expect_err("Expected to run out of memory");

        assert_stack_overflow(&error);
    }

    /// Test that when a transaction wasm goes over the wasm memory limit in the
    /// host input, the execution fails.
    #[test]
    fn test_tx_memory_limiter_in_host_input() {
        let mut state = TestState::default();
        let gas_meter =
            RefCell::new(TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()));
        let tx_index = TxIndex::default();

        let tx_no_op = TestWasms::TxNoOp.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&tx_no_op);
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let code_len = (tx_no_op.len() as u64).serialize_to_vec();
        state.write_log_mut().write(&key, tx_no_op.clone()).unwrap();
        state.write_log_mut().write(&len_key, code_len).unwrap();

        // Assuming 200 pages, 12.8 MiB limit
        assert_eq!(memory::TX_MEMORY_MAX_PAGES, 200);

        // Allocating `2^24` (16 MiB) for the input should be above the memory
        // limit and should fail
        let len = 2_usize.pow(24);
        let tx_data: Vec<u8> = vec![6_u8; len];
        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::cache();
        let (mut tx_cache, _) =
            wasm::compilation_cache::common::testing::cache();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::new(tx_no_op, None));
        outer_tx.set_data(Data::new(tx_data));
        let result = tx(
            &mut state,
            &gas_meter,
            &tx_index,
            &outer_tx,
            &mut vp_cache,
            &mut tx_cache,
        );
        // Depending on platform, we get a different error from the running out
        // of memory
        match result {
            // Dylib engine error (used anywhere except mac)
            Err(Error::MemoryError(memory::Error::MemoryOutOfBounds(
                wasmer::MemoryError::CouldNotGrow { .. },
            ))) => {}
            Err(error) => {
                let trap_code = get_trap_code(&error);
                // Universal engine error (currently used on mac)
                assert_eq!(
                    trap_code,
                    Either::Left(wasmer_vm::TrapCode::HeapAccessOutOfBounds)
                );
            }
            _ => panic!("Expected to run out of memory, got {:?}", result),
        }
    }

    /// Test that when a validity predicate wasm goes over the wasm memory limit
    /// in the host input, the execution fails.
    #[test]
    fn test_vp_memory_limiter_in_host_input() {
        let mut state = TestState::default();
        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();
        let tx_index = TxIndex::default();

        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&vp_code);
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        let code_len = (vp_code.len() as u64).serialize_to_vec();
        state.write_bytes(&key, vp_code).unwrap();
        state.write_bytes(&len_key, code_len).unwrap();

        // Assuming 200 pages, 12.8 MiB limit
        assert_eq!(memory::VP_MEMORY_MAX_PAGES, 200);

        // Allocating `2^24` (16 MiB) for the input should be above the memory
        // limit and should fail
        let len = 2_usize.pow(24);
        let tx_data: Vec<u8> = vec![6_u8; len];
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_data(Data::new(tx_data));
        outer_tx.set_code(Code::new(vec![], None));
        let (vp_cache, _) = wasm::compilation_cache::common::testing::cache();
        let result = vp(
            code_hash,
            &outer_tx,
            &tx_index,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache,
        );
        // Depending on platform, we get a different error from the running out
        // of memory
        match result {
            // Dylib engine error (used anywhere except mac)
            Err(Error::MemoryError(memory::Error::MemoryOutOfBounds(
                wasmer::MemoryError::CouldNotGrow { .. },
            ))) => {
                // as expected
            }
            Err(error) => {
                let trap_code = get_trap_code(&error);
                // Universal engine error (currently used on mac)
                assert_eq!(
                    trap_code,
                    Either::Left(wasmer_vm::TrapCode::HeapAccessOutOfBounds)
                );
            }
            _ => panic!("Expected to run out of memory, got {:?}", result),
        }
    }

    /// Test that when a transaction wasm goes over the wasm memory limit in the
    /// value returned from host environment call during wasm execution, the
    /// execution is aborted.
    #[test]
    fn test_tx_memory_limiter_in_host_env() {
        let mut state = TestState::default();
        let gas_meter =
            RefCell::new(TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()));
        let tx_index = TxIndex::default();

        let tx_read_key = TestWasms::TxReadStorageKey.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&tx_read_key);
        let code_len = (tx_read_key.len() as u64).serialize_to_vec();
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        state
            .write_log_mut()
            .write(&key, tx_read_key.clone())
            .unwrap();
        state.write_log_mut().write(&len_key, code_len).unwrap();

        // Allocating `2^24` (16 MiB) for a value in storage that the tx
        // attempts to read should be above the memory limit and should
        // fail
        let len = 2_usize.pow(24);
        let value: Vec<u8> = vec![6_u8; len];
        let key_raw = "key";
        let key = Key::parse(key_raw).unwrap();
        // Write the value that should be read by the tx into the storage. When
        // writing directly to storage, the value has to be encoded with
        // Borsh.
        state.write_bytes(&key, value.serialize_to_vec()).unwrap();
        let tx_data = key.serialize_to_vec();
        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::cache();
        let (mut tx_cache, _) =
            wasm::compilation_cache::common::testing::cache();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::new(tx_read_key, None));
        outer_tx.set_data(Data::new(tx_data));
        let error = tx(
            &mut state,
            &gas_meter,
            &tx_index,
            &outer_tx,
            &mut vp_cache,
            &mut tx_cache,
        )
        .expect_err("Expected to run out of memory");

        assert_stack_overflow(&error);
    }

    /// Test that when a validity predicate wasm goes over the wasm memory limit
    /// in the value returned from host environment call during wasm
    /// execution, the execution is aborted.
    #[test]
    fn test_vp_memory_limiter_in_host_env() {
        let mut state = TestState::default();
        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();
        let tx_index = TxIndex::default();

        let vp_read_key = TestWasms::VpReadStorageKey.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&vp_read_key);
        let code_len = (vp_read_key.len() as u64).serialize_to_vec();
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        state.write_bytes(&key, vp_read_key).unwrap();
        state.write_bytes(&len_key, code_len).unwrap();

        // Allocating `2^24` (16 MiB) for a value in storage that the tx
        // attempts to read should be above the memory limit and should
        // fail
        let len = 2_usize.pow(24);
        let value: Vec<u8> = vec![6_u8; len];
        let key_raw = "key";
        let key = Key::parse(key_raw).unwrap();
        // Write the value that should be read by the tx into the storage. When
        // writing directly to storage, the value has to be encoded with
        // Borsh.
        state.write_bytes(&key, value.serialize_to_vec()).unwrap();
        let tx_data = key.serialize_to_vec();
        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.header.chain_id = state.in_mem().chain_id.clone();
        outer_tx.set_data(Data::new(tx_data));
        outer_tx.set_code(Code::new(vec![], None));
        let (vp_cache, _) = wasm::compilation_cache::common::testing::cache();
        let error = vp(
            code_hash,
            &outer_tx,
            &tx_index,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache,
        )
        .expect_err("Expected to run out of memory");

        assert_stack_overflow(&error);
    }

    /// Test that when a validity predicate wasm goes over the wasm memory limit
    /// in the value returned from host environment call during wasm execution,
    /// inside the wasm execution calling `eval` host function, the `eval` fails
    /// and hence returns `false`.
    #[test]
    fn test_vp_memory_limiter_in_host_env_inside_guest_calling_eval() {
        let mut state = TestState::default();
        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();
        let tx_index = TxIndex::default();

        // This code will call `eval` with the other VP below
        let vp_eval = TestWasms::VpEval.read_bytes();
        // store the wasm code
        let code_hash = Hash::sha256(&vp_eval);
        let code_len = (vp_eval.len() as u64).serialize_to_vec();
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        state.write_bytes(&key, vp_eval).unwrap();
        state.write_bytes(&len_key, code_len).unwrap();
        // This code will read value from the storage
        let vp_read_key = TestWasms::VpReadStorageKey.read_bytes();
        // store the wasm code
        let read_code_hash = Hash::sha256(&vp_read_key);
        let code_len = (vp_read_key.len() as u64).serialize_to_vec();
        let key = Key::wasm_code(&read_code_hash);
        let len_key = Key::wasm_code_len(&read_code_hash);
        state.write_bytes(&key, vp_read_key).unwrap();
        state.write_bytes(&len_key, code_len).unwrap();

        // Allocating `2^24` (16 MiB) for a value in storage that the tx
        // attempts to read should be above the memory limit and should
        // fail
        let len = 2_usize.pow(24);
        let value: Vec<u8> = vec![6_u8; len];
        let key_raw = "key";
        let key = Key::parse(key_raw).unwrap();
        // Write the value that should be read by the tx into the storage. When
        // writing directly to storage, the value has to be encoded with
        // Borsh.
        state.write_bytes(&key, value.serialize_to_vec()).unwrap();
        let input = 2_usize.pow(23).serialize_to_vec();

        let mut tx = Tx::new(state.in_mem().chain_id.clone(), None);
        tx.add_code(vec![], None).add_serialized_data(input);

        let eval_vp = EvalVp {
            vp_code_hash: read_code_hash,
            input: tx,
        };

        let mut outer_tx = Tx::new(state.in_mem().chain_id.clone(), None);
        outer_tx.add_code(vec![], None).add_data(eval_vp);

        let (vp_cache, _) = wasm::compilation_cache::common::testing::cache();
        let passed = vp(
            code_hash,
            &outer_tx,
            &tx_index,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache,
        )
        .unwrap();
        assert!(!passed);
    }

    fn execute_tx_with_code(tx_code: Vec<u8>) -> Result<BTreeSet<Address>> {
        let tx_data = vec![];
        let tx_index = TxIndex::default();
        let mut state = TestState::default();
        let gas_meter =
            RefCell::new(TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()));
        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::cache();
        let (mut tx_cache, _) =
            wasm::compilation_cache::common::testing::cache();

        // store the tx code
        let code_hash = Hash::sha256(&tx_code);
        let code_len = (tx_code.len() as u64).serialize_to_vec();
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        state.write_log_mut().write(&key, tx_code).unwrap();
        state.write_log_mut().write(&len_key, code_len).unwrap();

        let mut outer_tx = Tx::from_type(TxType::Raw);
        outer_tx.set_code(Code::from_hash(code_hash, None));
        outer_tx.set_data(Data::new(tx_data));

        tx(
            &mut state,
            &gas_meter,
            &tx_index,
            &outer_tx,
            &mut vp_cache,
            &mut tx_cache,
        )
    }

    fn loop_in_tx_wasm(loops: u32) -> Result<BTreeSet<Address>> {
        // A transaction with a recursive loop.
        // The boilerplate code is generated from tx_template.wasm using
        // `wasm2wat` and the loop code is hand-written.
        let tx_code = wasmer::wat2wasm(
            format!(
                r#"
            (module
                (type (;0;) (func (param i64 i64)))

                ;; recursive loop, the param is the number of loops
                (func $loop (param i64) (result i64)
                (if
                (result i64)
                (i64.eqz (get_local 0))
                (then (get_local 0))
                (else (call $loop (i64.sub (get_local 0) (i64.const 1))))))

                (func $_apply_tx (type 0) (param i64 i64)
                (call $loop (i64.const {}))
                drop)

                (table (;0;) 1 1 funcref)
                (memory (;0;) 16)
                (global (;0;) (mut i32) (i32.const 1048576))
                (export "memory" (memory 0))
                (export "_apply_tx" (func $_apply_tx)))
            "#,
                loops
            )
            .as_bytes(),
        )
        .expect("unexpected error converting wat2wasm")
        .into_owned();

        execute_tx_with_code(tx_code)
    }

    fn loop_in_vp_wasm(loops: u32) -> Result<bool> {
        // A validity predicate with a recursive loop.
        // The boilerplate code is generated from vp_template.wasm using
        // `wasm2wat` and the loop code is hand-written.
        let vp_code = wasmer::wat2wasm(format!(
            r#"
            (module
                (type (;0;) (func (param i64 i64 i64 i64 i64 i64 i64 i64) (result i64)))

                ;; recursive loop, the param is the number of loops
                (func $loop (param i64) (result i64)
                (if
                (result i64)
                (i64.eqz (get_local 0))
                (then (get_local 0))
                (else (call $loop (i64.sub (get_local 0) (i64.const 1))))))

                (func $_validate_tx (type 0) (param i64 i64 i64 i64 i64 i64 i64 i64) (result i64)
                (call $loop (i64.const {})))

                (table (;0;) 1 1 funcref)
                (memory (;0;) 16)
                (global (;0;) (mut i32) (i32.const 1048576))
                (export "memory" (memory 0))
                (export "_validate_tx" (func $_validate_tx)))
            "#, loops).as_bytes(),
        )
            .expect("unexpected error converting wat2wasm").into_owned();

        let outer_tx = Tx::from_type(TxType::Raw);
        let tx_index = TxIndex::default();
        let mut state = TestState::default();
        let addr = state.in_mem_mut().address_gen.generate_address("rng seed");
        let gas_meter = RefCell::new(VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(TX_GAS_LIMIT.into()),
        ));
        let keys_changed = BTreeSet::new();
        let verifiers = BTreeSet::new();
        let (vp_cache, _) = wasm::compilation_cache::common::testing::cache();
        // store the vp code
        let code_hash = Hash::sha256(&vp_code);
        let code_len = (vp_code.len() as u64).serialize_to_vec();
        let key = Key::wasm_code(&code_hash);
        let len_key = Key::wasm_code_len(&code_hash);
        state.write_bytes(&key, vp_code).unwrap();
        state.write_bytes(&len_key, code_len).unwrap();

        vp(
            code_hash,
            &outer_tx,
            &tx_index,
            &addr,
            &state,
            &gas_meter,
            &keys_changed,
            &verifiers,
            vp_cache,
        )
    }

    fn get_trap_code(error: &Error) -> Either<TrapCode, String> {
        if let Error::RuntimeError(err) = error {
            if let Some(trap_code) = err.clone().to_trap() {
                Either::Left(trap_code)
            } else {
                Either::Right(format!("Missing trap code {}", err))
            }
        } else {
            Either::Right(format!("Unexpected error {}", error))
        }
    }

    fn assert_stack_overflow(error: &Error) {
        let trap_code = get_trap_code(error);
        // Depending on platform, we get a different error from the overflow
        assert!(
            // Universal engine error (currently used on mac)
            trap_code ==
                Either::Left(wasmer_vm::TrapCode::UnreachableCodeReached) ||
            // Dylib engine error (used elsewhere)
                trap_code ==
                Either::Left(wasmer_vm::TrapCode::StackOverflow),
        );
    }
}
