//! Wasm runners

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use parity_wasm::elements;
use pwasm_utils::{self, rules};
use thiserror::Error;
use wasmer::Instance;

use super::host_env::{
    prepare_mm_filter_imports, prepare_mm_imports, prepare_tx_imports,
    prepare_vp_env,
};
use crate::gossip::mm::MmHost;
use crate::ledger::gas::{BlockGasMeter, VpGasMeter};
use crate::ledger::storage::write_log::WriteLog;
use crate::ledger::storage::{self, Storage, StorageHasher};
use crate::proto::Tx;
use crate::types::address::Address;
use crate::types::internal::HostEnvResult;
use crate::types::storage::Key;
use crate::vm::host_env::VpEvalRunner;
use crate::vm::prefix_iter::PrefixIterators;
use crate::vm::types::{TxInput, VpInput};
use crate::vm::wasm::memory;
use crate::vm::{
    validate_untrusted_wasm, EnvHostSliceWrapper, EnvHostWrapper,
    MutEnvHostWrapper,
};

const TX_ENTRYPOINT: &str = "_apply_tx";
const VP_ENTRYPOINT: &str = "_validate_tx";
const MATCHMAKER_ENTRYPOINT: &str = "_match_intent";
const FILTER_ENTRYPOINT: &str = "_validate_intent";
const WASM_STACK_LIMIT: u32 = u16::MAX as u32;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    // 1. Common error types
    #[error("Memory error: {0}")]
    MemoryError(memory::Error),
    #[error("Unable to inject gas meter")]
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
    InstantiationError(wasmer::InstantiationError),
    #[error(
        "Unexpected module entrypoint interface {entrypoint}, failed with: \
         {error}"
    )]
    UnexpectedModuleEntrypointInterface {
        entrypoint: &'static str,
        error: wasmer::RuntimeError,
    },
    #[error("Wasm validation error: {0}")]
    ValidationError(wasmparser::BinaryReaderError),
}

/// Result for functions that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// Transaction wasm runner
#[derive(Clone, Debug)]
pub struct TxRunner {
    wasm_store: wasmer::Store,
}

impl TxRunner {
    /// TODO remove the `new`, it's not very useful
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // Use Singlepass compiler with the default settings
        let compiler = wasmer_compiler_singlepass::Singlepass::default();
        let limit = memory::tx_limit();
        // TODO Could we pass the modified accounts sub-spaces via WASM store
        // directly to VPs' wasm scripts to avoid passing it through the
        // host?
        let wasm_store = wasmer::Store::new_with_tunables(
            &wasmer_engine_jit::JIT::new(compiler).engine(),
            limit,
        );
        Self { wasm_store }
    }

    /// Execute a transaction code. Returns verifiers requested by the
    /// transaction.
    pub fn run<DB, H>(
        &self,
        storage: &Storage<DB, H>,
        write_log: &mut WriteLog,
        gas_meter: &mut BlockGasMeter,
        tx_code: Vec<u8>,
        tx_data: Vec<u8>,
    ) -> Result<HashSet<Address>>
    where
        DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
        H: 'static + StorageHasher,
    {
        validate_untrusted_wasm(&tx_code).map_err(Error::ValidationError)?;

        // This is not thread-safe, we're assuming single-threaded Tx runner.
        let storage = unsafe { EnvHostWrapper::new(storage) };
        // This is also not thread-safe, we're assuming single-threaded Tx
        // runner.
        let write_log = unsafe { MutEnvHostWrapper::new(write_log) };
        // This is also not thread-safe, we're assuming single-threaded Tx
        // runner.
        let mut iterators: PrefixIterators<'_, DB> = PrefixIterators::default();
        let iterators = unsafe { MutEnvHostWrapper::new(&mut iterators) };
        let mut verifiers = HashSet::new();
        // This is also not thread-safe, we're assuming single-threaded Tx
        // runner.
        let env_verifiers = unsafe { MutEnvHostWrapper::new(&mut verifiers) };
        // This is also not thread-safe, we're assuming single-threaded Tx
        // runner.
        let gas_meter = unsafe { MutEnvHostWrapper::new(gas_meter) };
        // This is also not thread-safe, we're assuming single-threaded Tx
        // runner.
        let mut result_buffer: Option<Vec<u8>> = None;
        let env_result_buffer =
            unsafe { MutEnvHostWrapper::new(&mut result_buffer) };

        let tx_code = prepare_wasm_code(&tx_code)?;

        let tx_module = wasmer::Module::new(&self.wasm_store, &tx_code)
            .map_err(Error::CompileError)?;
        let initial_memory = memory::prepare_tx_memory(&self.wasm_store)
            .map_err(Error::MemoryError)?;
        let tx_imports = prepare_tx_imports(
            &self.wasm_store,
            storage,
            write_log,
            iterators,
            env_verifiers,
            gas_meter,
            env_result_buffer,
            initial_memory,
        );

        // compile and run the transaction wasm code
        let tx_code = wasmer::Instance::new(&tx_module, &tx_imports)
            .map_err(Error::InstantiationError)?;
        Self::run_with_input(tx_code, tx_data)?;
        Ok(verifiers)
    }

    fn run_with_input(tx_code: Instance, tx_data: TxInput) -> Result<()> {
        // We need to write the inputs in the memory exported from the wasm
        // module
        let memory = tx_code
            .exports
            .get_memory("memory")
            .map_err(Error::MissingModuleMemory)?;
        let memory::TxCallInput {
            tx_data_ptr,
            tx_data_len,
        } = memory::write_tx_inputs(memory, tx_data)
            .map_err(Error::MemoryError)?;

        // Get the module's entrypoint to be called
        let apply_tx = tx_code
            .exports
            .get_function(TX_ENTRYPOINT)
            .map_err(Error::MissingModuleEntrypoint)?
            .native::<(u64, u64), ()>()
            .map_err(|error| Error::UnexpectedModuleEntrypointInterface {
                entrypoint: TX_ENTRYPOINT,
                error,
            })?;
        apply_tx
            .call(tx_data_ptr, tx_data_len)
            .map_err(Error::RuntimeError)
    }
}

/// Validity predicate wasm runner
#[derive(Clone, Debug)]
pub struct VpRunner {
    wasm_store: wasmer::Store,
}

impl VpRunner {
    /// TODO remove the `new`, it's not very useful
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // Use Singlepass compiler with the default settings
        let compiler = wasmer_compiler_singlepass::Singlepass::default();
        let limit = memory::vp_limit();
        // TODO: Maybe refactor wasm_store: not necessary to do in two steps
        let wasm_store = wasmer::Store::new_with_tunables(
            &wasmer_engine_jit::JIT::new(compiler).engine(),
            limit,
        );
        Self { wasm_store }
    }

    /// Execute a validity predicate code. Returns whether the validity
    /// predicate accepted storage modifications performed by the transaction
    /// that triggered the execution.
    // TODO consider using a wrapper object for all the host env references
    #[allow(clippy::too_many_arguments)]
    pub fn run<DB, H>(
        &self,
        vp_code: impl AsRef<[u8]>,
        tx: &Tx,
        address: &Address,
        storage: &Storage<DB, H>,
        write_log: &WriteLog,
        vp_gas_meter: &mut VpGasMeter,
        keys_changed: &[Key],
        verifiers: &HashSet<Address>,
    ) -> Result<bool>
    where
        DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
        H: 'static + StorageHasher,
    {
        validate_untrusted_wasm(vp_code.as_ref())
            .map_err(Error::ValidationError)?;
        let tx_data = tx.data.clone().unwrap_or_default();

        // Read-only access from parallel Vp runners
        let storage = unsafe { EnvHostWrapper::new(storage) };
        // Read-only access from parallel Vp runners
        let write_log = unsafe { EnvHostWrapper::new(write_log) };
        // Read-only access from parallel Vp runners
        let tx = unsafe { EnvHostWrapper::new(tx) };
        // This is not thread-safe, but because each VP has its own instance
        // there is no shared access
        let mut iterators: PrefixIterators<'_, DB> = PrefixIterators::default();
        let iterators = unsafe { MutEnvHostWrapper::new(&mut iterators) };
        // This is not thread-safe, but because each VP has its own instance
        // there is no shared access
        let gas_meter = unsafe { MutEnvHostWrapper::new(vp_gas_meter) };
        // Read-only access from parallel Vp runners
        let env_keys_changed =
            unsafe { EnvHostSliceWrapper::new(keys_changed) };
        // Read-only access from parallel Vp runners
        let env_verifiers = unsafe { EnvHostWrapper::new(verifiers) };
        // This is not thread-safe, but because each VP has its own instance
        // there is no shared access
        let mut result_buffer: Option<Vec<u8>> = None;
        let env_result_buffer =
            unsafe { MutEnvHostWrapper::new(&mut result_buffer) };

        let eval_runner = VpEval {
            address: address.clone(),
            storage: storage.clone(),
            write_log: write_log.clone(),
            iterators: iterators.clone(),
            gas_meter: gas_meter.clone(),
            tx: tx.clone(),
            keys_changed: env_keys_changed.clone(),
            verifiers: env_verifiers.clone(),
            result_buffer: env_result_buffer.clone(),
        };
        // Assuming single-threaded VP wasm runner
        let eval_runner = unsafe { EnvHostWrapper::new(&eval_runner) };

        let vp_code = prepare_wasm_code(vp_code)?;

        let vp_module = wasmer::Module::new(&self.wasm_store, &vp_code)
            .map_err(Error::CompileError)?;
        let initial_memory = memory::prepare_vp_memory(&self.wasm_store)
            .map_err(Error::MemoryError)?;
        let input: VpInput = VpInput {
            addr: &address,
            data: tx_data.as_ref(),
            keys_changed,
            verifiers,
        };
        let vp_imports = prepare_vp_env(
            &self.wasm_store,
            address.clone(),
            storage,
            write_log,
            iterators,
            gas_meter,
            tx,
            eval_runner,
            env_result_buffer,
            initial_memory,
        );

        // compile and run the transaction wasm code
        let vp_instance = wasmer::Instance::new(&vp_module, &vp_imports)
            .map_err(Error::InstantiationError)?;
        VpRunner::run_with_input(vp_instance, input)
    }

    fn run_with_input(vp_code: Instance, input: VpInput) -> Result<bool> {
        // We need to write the inputs in the memory exported from the wasm
        // module
        let memory = vp_code
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
        } = memory::write_vp_inputs(memory, input)
            .map_err(Error::MemoryError)?;

        // Get the module's entrypoint to be called
        let validate_tx = vp_code
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
}

/// Validity predicate wasm runner from `eval` function calls.
pub struct VpEval<'a, DB, H>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    /// The address of the validity predicate that called the `eval`
    pub address: Address,
    /// Read-only access to the storage.
    pub storage: EnvHostWrapper<'a, &'a Storage<DB, H>>,
    /// Read-only access to the write log.
    pub write_log: EnvHostWrapper<'a, &'a WriteLog>,
    /// Storage prefix iterators.
    pub iterators: MutEnvHostWrapper<'a, &'a PrefixIterators<'a, DB>>,
    /// VP gas meter.
    pub gas_meter: MutEnvHostWrapper<'a, &'a VpGasMeter>,
    /// The transaction code.
    pub tx: EnvHostWrapper<'a, &'a Tx>,
    /// The storage keys that have been changed.
    pub keys_changed: EnvHostSliceWrapper<'a, &'a [Key]>,
    /// The verifiers whose validity predicates should be triggered.
    pub verifiers: EnvHostWrapper<'a, &'a HashSet<Address>>,
    /// Cache for 2-step reads from host environment.
    pub result_buffer: MutEnvHostWrapper<'a, &'a Option<Vec<u8>>>,
}

impl<DB, H> VpEvalRunner for VpEval<'static, DB, H>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn eval(&self, vp_code: Vec<u8>, input_data: Vec<u8>) -> HostEnvResult {
        match self.run_eval(vp_code, input_data) {
            Ok(ok) => HostEnvResult::from(ok),
            Err(err) => {
                tracing::error!("VP eval error {}", err);
                HostEnvResult::Fail
            }
        }
    }
}

impl<DB, H> VpEval<'static, DB, H>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn run_eval(&self, vp_code: Vec<u8>, input_data: Vec<u8>) -> Result<bool> {
        // TODO more code re-use with VpRunner
        validate_untrusted_wasm(&vp_code).map_err(Error::ValidationError)?;

        // Use Singlepass compiler with the default settings
        let compiler = wasmer_compiler_singlepass::Singlepass::default();
        let limit = memory::vp_limit();
        let wasm_store = wasmer::Store::new_with_tunables(
            &wasmer_engine_jit::JIT::new(compiler).engine(),
            limit,
        );

        let eval_runner = VpEval {
            address: self.address.clone(),
            storage: self.storage.clone(),
            write_log: self.write_log.clone(),
            iterators: self.iterators.clone(),
            gas_meter: self.gas_meter.clone(),
            tx: self.tx.clone(),
            keys_changed: self.keys_changed.clone(),
            verifiers: self.verifiers.clone(),
            result_buffer: self.result_buffer.clone(),
        };
        // Assuming single-threaded VP wasm runner
        let eval_runner = unsafe { EnvHostWrapper::new(&eval_runner) };

        let vp_code = prepare_wasm_code(vp_code)?;

        let vp_module = wasmer::Module::new(&wasm_store, &vp_code)
            .map_err(Error::CompileError)?;
        let initial_memory = memory::prepare_vp_memory(&wasm_store)
            .map_err(Error::MemoryError)?;
        let addr = &self.address;
        let keys_changed = unsafe { self.keys_changed.get() };
        let verifiers = unsafe { self.verifiers.get() };
        let input: VpInput = VpInput {
            addr,
            data: &input_data[..],
            keys_changed,
            verifiers,
        };
        let vp_imports = prepare_vp_env(
            &wasm_store,
            addr.clone(),
            self.storage.clone(),
            self.write_log.clone(),
            self.iterators.clone(),
            self.gas_meter.clone(),
            self.tx.clone(),
            eval_runner,
            self.result_buffer.clone(),
            initial_memory,
        );

        // compile and run the transaction wasm code
        let vp_instance = wasmer::Instance::new(&vp_module, &vp_imports)
            .map_err(Error::InstantiationError)?;
        VpRunner::run_with_input(vp_instance, input)
    }
}

/// Matchmaker wasm runner.
#[derive(Clone, Debug)]
pub struct MmRunner {
    wasm_store: wasmer::Store,
}

impl MmRunner {
    /// TODO remove the `new`, it's not very useful
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // TODO for the matchmaker we could use a compiler that does more
        // optimisation.
        let compiler = wasmer_compiler_singlepass::Singlepass::default();
        let wasm_store =
            wasmer::Store::new(&wasmer_engine_jit::JIT::new(compiler).engine());
        Self { wasm_store }
    }

    /// Execute a matchmaker code.
    pub fn run<MM>(
        &self,
        matchmaker_code: impl AsRef<[u8]>,
        data: impl AsRef<[u8]>,
        intent_id: impl AsRef<[u8]>,
        intent_data: impl AsRef<[u8]>,
        mm: Arc<Mutex<MM>>,
    ) -> Result<bool>
    where
        MM: 'static + MmHost,
    {
        let matchmaker_module: wasmer::Module =
            wasmer::Module::new(&self.wasm_store, &matchmaker_code)
                .map_err(Error::CompileError)?;

        let initial_memory =
            memory::prepare_matchmaker_memory(&self.wasm_store)
                .map_err(Error::MemoryError)?;

        let matchmaker_imports =
            prepare_mm_imports(&self.wasm_store, initial_memory, mm);

        // compile and run the matchmaker wasm code
        let matchmaker_code =
            wasmer::Instance::new(&matchmaker_module, &matchmaker_imports)
                .map_err(Error::InstantiationError)?;

        Self::run_with_input(&matchmaker_code, data, intent_id, intent_data)
    }

    fn run_with_input(
        code: &Instance,
        data: impl AsRef<[u8]>,
        intent_id: impl AsRef<[u8]>,
        intent_data: impl AsRef<[u8]>,
    ) -> Result<bool> {
        let memory = code
            .exports
            .get_memory("memory")
            .map_err(Error::MissingModuleMemory)?;
        let memory::MatchmakerCallInput {
            data_ptr,
            data_len,
            intent_id_ptr,
            intent_id_len,
            intent_data_ptr,
            intent_data_len,
        }: memory::MatchmakerCallInput = memory::write_matchmaker_inputs(
            &memory,
            data,
            intent_id,
            intent_data,
        )
        .map_err(Error::MemoryError)?;
        let apply_matchmaker = code
            .exports
            .get_function(MATCHMAKER_ENTRYPOINT)
            .map_err(Error::MissingModuleEntrypoint)?
            .native::<(u64, u64, u64, u64, u64, u64), u64>()
            .map_err(|error| Error::UnexpectedModuleEntrypointInterface {
                entrypoint: MATCHMAKER_ENTRYPOINT,
                error,
            })?;
        let found_match = apply_matchmaker
            .call(
                data_ptr,
                data_len,
                intent_id_ptr,
                intent_id_len,
                intent_data_ptr,
                intent_data_len,
            )
            .map_err(Error::RuntimeError)?;
        Ok(found_match == 0)
    }
}

/// Matchmaker's filter wasm runner
#[derive(Clone, Debug)]
pub struct MmFilterRunner {
    wasm_store: wasmer::Store,
}

impl MmFilterRunner {
    /// TODO remove the `new`, it's not very useful
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // TODO replace to use a better compiler because this program is local
        let compiler = wasmer_compiler_singlepass::Singlepass::default();
        let wasm_store =
            wasmer::Store::new(&wasmer_engine_jit::JIT::new(compiler).engine());
        Self { wasm_store }
    }

    /// Execute a matchmaker filter code to check if it accepts the given
    /// intent.
    pub fn run(
        &self,
        code: impl AsRef<[u8]>,
        intent_data: impl AsRef<[u8]>,
    ) -> Result<bool> {
        validate_untrusted_wasm(code.as_ref())
            .map_err(Error::ValidationError)?;
        let code = prepare_wasm_code(code)?;
        let filter_module: wasmer::Module =
            wasmer::Module::new(&self.wasm_store, &code)
                .map_err(Error::CompileError)?;
        let initial_memory = memory::prepare_filter_memory(&self.wasm_store)
            .map_err(Error::MemoryError)?;

        let filter_imports =
            prepare_mm_filter_imports(&self.wasm_store, initial_memory);
        let filter_code =
            wasmer::Instance::new(&filter_module, &filter_imports)
                .map_err(Error::InstantiationError)?;

        Self::run_with_input(&filter_code, intent_data)
    }

    fn run_with_input(
        code: &Instance,
        intent_data: impl AsRef<[u8]>,
    ) -> Result<bool> {
        let memory = code
            .exports
            .get_memory("memory")
            .map_err(Error::MissingModuleMemory)?;
        let memory::FilterCallInput {
            intent_data_ptr,
            intent_data_len,
        }: memory::FilterCallInput =
            memory::write_filter_inputs(&memory, intent_data)
                .map_err(Error::MemoryError)?;
        let apply_filter = code
            .exports
            .get_function(FILTER_ENTRYPOINT)
            .map_err(Error::MissingModuleEntrypoint)?
            .native::<(u64, u64), u64>()
            .map_err(|error| Error::UnexpectedModuleEntrypointInterface {
                entrypoint: FILTER_ENTRYPOINT,
                error,
            })?;
        let found_match = apply_filter
            .call(intent_data_ptr, intent_data_len)
            .map_err(Error::RuntimeError)?;
        Ok(found_match == 0)
    }
}

/// Inject gas counter and stack-height limiter into the given wasm code
fn prepare_wasm_code<T: AsRef<[u8]>>(code: T) -> Result<Vec<u8>> {
    let module: elements::Module = elements::deserialize_buffer(code.as_ref())
        .map_err(Error::DeserializationError)?;
    let module =
        pwasm_utils::inject_gas_counter(module, &get_gas_rules(), "env")
            .map_err(|_original_module| Error::GasMeterInjection)?;
    let module =
        pwasm_utils::stack_height::inject_limiter(module, WASM_STACK_LIMIT)
            .map_err(|_original_module| Error::StackLimiterInjection)?;
    elements::serialize(module).map_err(Error::SerializationError)
}

/// Get the gas rules used to meter wasm operations
fn get_gas_rules() -> rules::Set {
    rules::Set::default().with_grow_cost(1)
}

#[cfg(test)]
mod tests {
    use borsh::BorshSerialize;
    use itertools::Either;
    use test_env_log::test;
    use wasmer_vm::TrapCode;

    use super::*;
    use crate::ledger::storage::testing::TestStorage;
    use crate::types::validity_predicate::EvalVp;

    const TX_MEMORY_LIMIT_WASM: &str = "../wasm_for_tests/tx_memory_limit.wasm";
    const TX_NO_OP_WASM: &str = "../wasm_for_tests/tx_no_op.wasm";
    const TX_READ_STORAGE_KEY_WASM: &str =
        "../wasm_for_tests/tx_read_storage_key.wasm";
    const VP_ALWAYS_TRUE_WASM: &str = "../wasm_for_tests/vp_always_true.wasm";
    const VP_EVAL_WASM: &str = "../wasm_for_tests/vp_eval.wasm";
    const VP_MEMORY_LIMIT_WASM: &str = "../wasm_for_tests/vp_memory_limit.wasm";
    const VP_READ_STORAGE_KEY_WASM: &str =
        "../wasm_for_tests/vp_read_storage_key.wasm";

    /// Test that when a transaction wasm goes over the stack-height limit, the
    /// execution is aborted.
    #[test]
    fn test_tx_stack_limiter() {
        // Because each call into `$loop` inside the wasm consumes 3 stack
        // heights, this should hit the stack limit. If we were to subtract
        // one from this value, we should be just under the limit.
        let loops = WASM_STACK_LIMIT / 3 - 1;

        let error = loop_in_tx_wasm(loops).expect_err(&format!(
            "Expecting runtime error \"unreachable\" caused by stack-height \
             overflow, loops {}. Got",
            loops,
        ));
        assert_eq!(
            get_trap_code(&error),
            Either::Left(wasmer_vm::TrapCode::UnreachableCodeReached),
        );

        // one less loop shouldn't go over the limit
        let result = loop_in_tx_wasm(loops - 1);
        assert!(result.is_ok(), "Expected success. Got {:?}", result);
    }

    /// Test that when a VP wasm goes over the stack-height limit, the execution
    /// is aborted.
    #[test]
    fn test_vp_stack_limiter() {
        // Because each call into `$loop` inside the wasm consumes 3 stack
        // heights, this should hit the stack limit. If we were to subtract
        // one from this value, we should be just under the limit.
        let loops = WASM_STACK_LIMIT / 3 - 1;

        let error = loop_in_vp_wasm(loops).expect_err(
            "Expecting runtime error \"unreachable\" caused by stack-height \
             overflow. Got",
        );
        assert_eq!(
            get_trap_code(&error),
            Either::Left(wasmer_vm::TrapCode::UnreachableCodeReached),
        );

        // one less loop shouldn't go over the limit
        let result = loop_in_vp_wasm(loops - 1);
        assert!(result.is_ok(), "Expected success. Got {:?}", result);
    }

    /// Test that when a transaction wasm goes over the memory limit inside the
    /// wasm execution, the execution is aborted.
    #[test]
    fn test_tx_memory_limiter_in_guest() {
        let runner = TxRunner::new();
        let storage = TestStorage::default();
        let mut write_log = WriteLog::default();
        let mut gas_meter = BlockGasMeter::default();

        // This code will allocate memory of the given size
        let tx_code =
            std::fs::read(TX_MEMORY_LIMIT_WASM).expect("cannot load wasm");

        // Assuming 200 pages, 12.8 MiB limit
        assert_eq!(memory::TX_MEMORY_MAX_PAGES, 200);

        // Allocating `2^23` (8 MiB) should be below the memory limit and
        // shouldn't fail
        let tx_data = 2_usize.pow(23).try_to_vec().unwrap();
        let result = runner.run(
            &storage,
            &mut write_log,
            &mut gas_meter,
            tx_code.clone(),
            tx_data,
        );
        assert!(result.is_ok(), "Expected success, got {:?}", result);

        // Allocating `2^24` (16 MiB) should be above the memory limit and
        // should fail
        let tx_data = 2_usize.pow(24).try_to_vec().unwrap();
        let error = runner
            .run(&storage, &mut write_log, &mut gas_meter, tx_code, tx_data)
            .expect_err("Expected to run out of memory");
        assert_eq!(
            get_trap_code(&error),
            Either::Left(wasmer_vm::TrapCode::UnreachableCodeReached),
        );
    }

    /// Test that when a validity predicate wasm goes over the memory limit
    /// inside the wasm execution when calling `eval` host function, the `eval`
    /// fails and hence returns `false`.
    #[test]
    fn test_vp_memory_limiter_in_guest_calling_eval() {
        let runner = VpRunner::new();
        let mut storage = TestStorage::default();
        let addr = storage.address_gen.generate_address("rng seed");
        let write_log = WriteLog::default();
        let mut gas_meter = VpGasMeter::new(0);
        let keys_changed = vec![];
        let verifiers = HashSet::new();

        // This code will call `eval` with the other VP below
        let vp_eval = std::fs::read(VP_EVAL_WASM).expect("cannot load wasm");
        // This code will allocate memory of the given size
        let vp_memory_limit =
            std::fs::read(VP_MEMORY_LIMIT_WASM).expect("cannot load wasm");

        // Assuming 200 pages, 12.8 MiB limit
        assert_eq!(memory::VP_MEMORY_MAX_PAGES, 200);

        // Allocating `2^23` (8 MiB) should be below the memory limit and
        // shouldn't fail
        let input = 2_usize.pow(23).try_to_vec().unwrap();
        let eval_vp = EvalVp {
            vp_code: vp_memory_limit.clone(),
            input,
        };
        let tx_data = eval_vp.try_to_vec().unwrap();
        let tx = Tx::new(vec![], Some(tx_data));
        // When the `eval`ed VP doesn't run out of memory, it should return
        // `true`
        let passed = runner
            .run(
                vp_eval.clone(),
                &tx,
                &addr,
                &storage,
                &write_log,
                &mut gas_meter,
                &keys_changed[..],
                &verifiers,
            )
            .unwrap();
        assert!(passed);

        // Allocating `2^24` (16 MiB) should be above the memory limit and
        // should fail
        let input = 2_usize.pow(24).try_to_vec().unwrap();
        let eval_vp = EvalVp {
            vp_code: vp_memory_limit,
            input,
        };
        let tx_data = eval_vp.try_to_vec().unwrap();
        let tx = Tx::new(vec![], Some(tx_data));
        // When the `eval`ed VP runs out of memory, its result should be
        // `false`, hence we should also get back `false` from the VP that
        // called `eval`.
        let passed = runner
            .run(
                vp_eval,
                &tx,
                &addr,
                &storage,
                &write_log,
                &mut gas_meter,
                &keys_changed[..],
                &verifiers,
            )
            .unwrap();

        assert!(!passed);
    }

    /// Test that when a validity predicate wasm goes over the memory limit
    /// inside the wasm execution, the execution is aborted.
    #[test]
    fn test_vp_memory_limiter_in_guest() {
        let runner = VpRunner::new();
        let mut storage = TestStorage::default();
        let addr = storage.address_gen.generate_address("rng seed");
        let write_log = WriteLog::default();
        let mut gas_meter = VpGasMeter::new(0);
        let keys_changed = vec![];
        let verifiers = HashSet::new();

        // This code will allocate memory of the given size
        let vp_code =
            std::fs::read(VP_MEMORY_LIMIT_WASM).expect("cannot load wasm");

        // Assuming 200 pages, 12.8 MiB limit
        assert_eq!(memory::VP_MEMORY_MAX_PAGES, 200);

        // Allocating `2^23` (8 MiB) should be below the memory limit and
        // shouldn't fail
        let tx_data = 2_usize.pow(23).try_to_vec().unwrap();
        let tx = Tx::new(vec![], Some(tx_data));
        let result = runner.run(
            vp_code.clone(),
            &tx,
            &addr,
            &storage,
            &write_log,
            &mut gas_meter,
            &keys_changed[..],
            &verifiers,
        );
        assert!(result.is_ok(), "Expected success, got {:?}", result);

        // Allocating `2^24` (16 MiB) should be above the memory limit and
        // should fail
        let tx_data = 2_usize.pow(24).try_to_vec().unwrap();
        let tx = Tx::new(vec![], Some(tx_data));
        let error = runner
            .run(
                vp_code,
                &tx,
                &addr,
                &storage,
                &write_log,
                &mut gas_meter,
                &keys_changed[..],
                &verifiers,
            )
            .expect_err("Expected to run out of memory");

        assert_eq!(
            get_trap_code(&error),
            Either::Left(wasmer_vm::TrapCode::UnreachableCodeReached),
        );
    }

    /// Test that when a transaction wasm goes over the wasm memory limit in the
    /// host input, the execution fails.
    #[test]
    fn test_tx_memory_limiter_in_host_input() {
        let runner = TxRunner::new();
        let storage = TestStorage::default();
        let mut write_log = WriteLog::default();
        let mut gas_meter = BlockGasMeter::default();

        let tx_no_op = std::fs::read(TX_NO_OP_WASM).expect("cannot load wasm");

        // Assuming 200 pages, 12.8 MiB limit
        assert_eq!(memory::TX_MEMORY_MAX_PAGES, 200);

        // Allocating `2^24` (16 MiB) for the input should be above the memory
        // limit and should fail
        let len = 2_usize.pow(24);
        let tx_data: Vec<u8> = vec![6_u8; len];
        let result = runner.run(
            &storage,
            &mut write_log,
            &mut gas_meter,
            tx_no_op,
            tx_data,
        );
        match result {
            Err(Error::MemoryError(memory::Error::MemoryOutOfBounds(
                wasmer::MemoryError::CouldNotGrow { .. },
            ))) => {
                // as expected
            }
            _ => panic!("Expected to run out of memory, got {:?}", result),
        }
    }

    /// Test that when a validity predicate wasm goes over the wasm memory limit
    /// in the host input, the execution fails.
    #[test]
    fn test_vp_memory_limiter_in_host_input() {
        let runner = VpRunner::new();
        let mut storage = TestStorage::default();
        let addr = storage.address_gen.generate_address("rng seed");
        let write_log = WriteLog::default();
        let mut gas_meter = VpGasMeter::new(0);
        let keys_changed = vec![];
        let verifiers = HashSet::new();

        let vp_code =
            std::fs::read(VP_ALWAYS_TRUE_WASM).expect("cannot load wasm");

        // Assuming 200 pages, 12.8 MiB limit
        assert_eq!(memory::VP_MEMORY_MAX_PAGES, 200);

        // Allocating `2^24` (16 MiB) for the input should be above the memory
        // limit and should fail
        let len = 2_usize.pow(24);
        let tx_data: Vec<u8> = vec![6_u8; len];
        let tx = Tx::new(vec![], Some(tx_data));
        let result = runner.run(
            vp_code,
            &tx,
            &addr,
            &storage,
            &write_log,
            &mut gas_meter,
            &keys_changed[..],
            &verifiers,
        );
        match result {
            Err(Error::MemoryError(memory::Error::MemoryOutOfBounds(
                wasmer::MemoryError::CouldNotGrow { .. },
            ))) => {
                // as expected
            }
            _ => panic!("Expected to run out of memory, got {:?}", result),
        }
    }

    /// Test that when a transaction wasm goes over the wasm memory limit in the
    /// value returned from host environment call during wasm execution, the
    /// execution is aborted.
    #[test]
    fn test_tx_memory_limiter_in_host_env() {
        let runner = TxRunner::new();
        let mut storage = TestStorage::default();
        let mut write_log = WriteLog::default();
        let mut gas_meter = BlockGasMeter::default();

        let tx_read_key =
            std::fs::read(TX_READ_STORAGE_KEY_WASM).expect("cannot load wasm");

        // Allocating `2^24` (16 MiB) for a value in storage that the tx
        // attempts to read should be above the memory limit and should
        // fail
        let len = 2_usize.pow(24);
        let value: Vec<u8> = vec![6_u8; len];
        let key_raw = "key";
        let key = Key::parse(key_raw.to_string()).unwrap();
        // Write the value that should be read by the tx into the storage. When
        // writing directly to storage, the value has to be encoded with
        // Borsh.
        storage.write(&key, value.try_to_vec().unwrap()).unwrap();
        let tx_data = key.try_to_vec().unwrap();
        let error = runner
            .run(
                &storage,
                &mut write_log,
                &mut gas_meter,
                tx_read_key,
                tx_data,
            )
            .expect_err("Expected to run out of memory");
        assert_eq!(
            get_trap_code(&error),
            Either::Left(wasmer_vm::TrapCode::UnreachableCodeReached),
        );
    }

    /// Test that when a validity predicate wasm goes over the wasm memory limit
    /// in the value returned from host environment call during wasm
    /// execution, the execution is aborted.
    #[test]
    fn test_vp_memory_limiter_in_host_env() {
        let runner = VpRunner::new();
        let mut storage = TestStorage::default();
        let addr = storage.address_gen.generate_address("rng seed");
        let write_log = WriteLog::default();
        let mut gas_meter = VpGasMeter::new(0);
        let keys_changed = vec![];
        let verifiers = HashSet::new();

        let vp_read_key =
            std::fs::read(VP_READ_STORAGE_KEY_WASM).expect("cannot load wasm");

        // Allocating `2^24` (16 MiB) for a value in storage that the tx
        // attempts to read should be above the memory limit and should
        // fail
        let len = 2_usize.pow(24);
        let value: Vec<u8> = vec![6_u8; len];
        let key_raw = "key";
        let key = Key::parse(key_raw.to_string()).unwrap();
        // Write the value that should be read by the tx into the storage. When
        // writing directly to storage, the value has to be encoded with
        // Borsh.
        storage.write(&key, value.try_to_vec().unwrap()).unwrap();
        let tx_data = key.try_to_vec().unwrap();
        let tx = Tx::new(vec![], Some(tx_data));
        let error = runner
            .run(
                vp_read_key,
                &tx,
                &addr,
                &storage,
                &write_log,
                &mut gas_meter,
                &keys_changed[..],
                &verifiers,
            )
            .expect_err("Expected to run out of memory");
        assert_eq!(
            get_trap_code(&error),
            Either::Left(wasmer_vm::TrapCode::UnreachableCodeReached),
        );
    }

    /// Test that when a validity predicate wasm goes over the wasm memory limit
    /// in the value returned from host environment call during wasm execution,
    /// inside the wasm execution calling `eval` host function, the `eval` fails
    /// and hence returns `false`.
    #[test]
    fn test_vp_memory_limiter_in_host_env_inside_guest_calling_eval() {
        let runner = VpRunner::new();
        let mut storage = TestStorage::default();
        let addr = storage.address_gen.generate_address("rng seed");
        let write_log = WriteLog::default();
        let mut gas_meter = VpGasMeter::new(0);
        let keys_changed = vec![];
        let verifiers = HashSet::new();

        // This code will call `eval` with the other VP below
        let vp_eval = std::fs::read(VP_EVAL_WASM).expect("cannot load wasm");
        // This code will read value from the storage
        let vp_read_key =
            std::fs::read(VP_READ_STORAGE_KEY_WASM).expect("cannot load wasm");

        // Allocating `2^24` (16 MiB) for a value in storage that the tx
        // attempts to read should be above the memory limit and should
        // fail
        let len = 2_usize.pow(24);
        let value: Vec<u8> = vec![6_u8; len];
        let key_raw = "key";
        let key = Key::parse(key_raw.to_string()).unwrap();
        // Write the value that should be read by the tx into the storage. When
        // writing directly to storage, the value has to be encoded with
        // Borsh.
        storage.write(&key, value.try_to_vec().unwrap()).unwrap();
        let input = 2_usize.pow(23).try_to_vec().unwrap();
        let eval_vp = EvalVp {
            vp_code: vp_read_key,
            input,
        };
        let tx_data = eval_vp.try_to_vec().unwrap();
        let tx = Tx::new(vec![], Some(tx_data));
        let passed = runner
            .run(
                vp_eval,
                &tx,
                &addr,
                &storage,
                &write_log,
                &mut gas_meter,
                &keys_changed[..],
                &verifiers,
            )
            .unwrap();
        assert!(!passed);
    }

    fn loop_in_tx_wasm(loops: u32) -> Result<HashSet<Address>> {
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

        let runner = TxRunner::new();
        let tx_data = vec![];
        let storage = TestStorage::default();
        let mut write_log = WriteLog::default();
        let mut gas_meter = BlockGasMeter::default();
        runner.run(&storage, &mut write_log, &mut gas_meter, tx_code, tx_data)
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

        let runner = VpRunner::new();
        let tx = Tx::new(vec![], None);
        let mut storage = TestStorage::default();
        let addr = storage.address_gen.generate_address("rng seed");
        let write_log = WriteLog::default();
        let mut gas_meter = VpGasMeter::new(0);
        let keys_changed = vec![];
        let verifiers = HashSet::new();
        runner.run(
            vp_code,
            &tx,
            &addr,
            &storage,
            &write_log,
            &mut gas_meter,
            &keys_changed[..],
            &verifiers,
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
}
