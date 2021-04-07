pub mod host_env;
mod memory;

use std::ffi::c_void;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use anoma::protobuf::types::Tx;
use anoma_vm_env::memory::{TxInput, VpInput};
use parity_wasm::elements;
use pwasm_utils::{self, rules};
use thiserror::Error;
use tokio::sync::mpsc::Sender;
use wasmer::Instance;
use wasmparser::{Validator, WasmFeatures};

use self::host_env::write_log::WriteLog;
use crate::shell::gas::BlockGasMeter;
use crate::shell::storage::{Address, Storage};

const TX_ENTRYPOINT: &str = "_apply_tx";
const VP_ENTRYPOINT: &str = "_validate_tx";
const MATCHMAKER_ENTRYPOINT: &str = "_match_intent";
const WASM_STACK_LIMIT: u32 = u16::MAX as u32;

/// This is used to attach the Ledger's host structures to transaction, which is
/// used for implementing some host calls. It's not thread-safe, we're assuming
/// single-threaded Tx runner.
pub struct TxEnvHostWrapper<T>(*mut c_void, PhantomData<T>);
unsafe impl<T> Send for TxEnvHostWrapper<T> {}
unsafe impl<T> Sync for TxEnvHostWrapper<T> {}

// Have to manually implement [`Clone`], because the derived [`Clone`] for
// [`PhantomData<T>`] puts the bound on [`T: Clone`]. Relevant issue: <https://github.com/rust-lang/rust/issues/26925>
impl<T> Clone for TxEnvHostWrapper<T> {
    fn clone(&self) -> Self {
        Self(self.0, PhantomData)
    }
}

impl<T> TxEnvHostWrapper<T> {
    /// This is not thread-safe, see [`TxEnvHostWrapper`]
    unsafe fn new(host_structure: *mut c_void) -> Self {
        Self(host_structure, PhantomData)
    }

    /// This is not thread-safe, see [`TxEnvHostWrapper`]
    pub unsafe fn get(&self) -> *mut T {
        self.0 as *mut T
    }
}
/// This is used to attach the Ledger's host structures to validity predicate
/// environment, which is used for implementing some host calls. It's not
/// thread-safe, we're assuming read-only access from parallel Vp runners.
pub struct VpEnvHostWrapper<T>(*const c_void, PhantomData<T>);
unsafe impl<T> Send for VpEnvHostWrapper<T> {}
unsafe impl<T> Sync for VpEnvHostWrapper<T> {}

// Same as for [`TxEnvHostWrapper`], we have to manually implement [`Clone`],
// because the derived [`Clone`] for [`PhantomData<T>`] puts the bound on [`T:
// Clone`].
impl<T> Clone for VpEnvHostWrapper<T> {
    fn clone(&self) -> Self {
        Self(self.0, PhantomData)
    }
}

impl<T> VpEnvHostWrapper<T> {
    /// This is not thread-safe, see [`VpEnvHostWrapper`]
    unsafe fn new(host_structure: *const c_void) -> Self {
        Self(host_structure, PhantomData)
    }

    /// This is not thread-safe, see [`VpEnvHostWrapper`]
    #[allow(dead_code)]
    pub unsafe fn get(&self) -> *const T {
        self.0 as *const T
    }
}

#[derive(Clone, Debug)]
pub struct TxRunner {
    wasm_store: wasmer::Store,
}

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

pub type Result<T> = std::result::Result<T, Error>;

impl TxRunner {
    pub fn new() -> Self {
        // Use Singlepass compiler with the default settings
        let compiler = wasmer_compiler_singlepass::Singlepass::default();
        // TODO Could we pass the modified accounts sub-spaces via WASM store
        // directly to VPs' wasm scripts to avoid passing it through the
        // host?
        let wasm_store =
            wasmer::Store::new(&wasmer_engine_jit::JIT::new(compiler).engine());
        Self { wasm_store }
    }

    pub fn run(
        &self,
        storage: &mut Storage,
        write_log: &mut WriteLog,
        gas_meter: &mut BlockGasMeter,
        tx_code: Vec<u8>,
        tx_data: &Vec<u8>,
    ) -> Result<()> {
        validate_wasm(&tx_code)?;

        // This is not thread-safe, we're assuming single-threaded Tx runner.
        let env_storage =
            unsafe { TxEnvHostWrapper::new(storage as *mut _ as *mut c_void) };
        // This is also not thread-safe, we're assuming single-threaded Tx
        // runner.
        let write_log = unsafe {
            TxEnvHostWrapper::new(write_log as *mut _ as *mut c_void)
        };
        // This is also not thread-safe, we're assuming single-threaded Tx
        // runner.
        let gas_meter = unsafe {
            TxEnvHostWrapper::new(gas_meter as *mut _ as *mut c_void)
        };

        let tx_code = prepare_wasm_code(&tx_code)?;

        let tx_module = wasmer::Module::new(&self.wasm_store, &tx_code)
            .map_err(Error::CompileError)?;
        let initial_memory = memory::prepare_tx_memory(&self.wasm_store)
            .map_err(Error::MemoryError)?;
        let tx_imports = host_env::prepare_tx_imports(
            &self.wasm_store,
            env_storage,
            write_log,
            gas_meter,
            initial_memory,
        );

        // compile and run the transaction wasm code
        let tx_code = wasmer::Instance::new(&tx_module, &tx_imports)
            .map_err(Error::InstantiationError)?;
        let ret = Self::run_with_input(tx_code, tx_data);

        // post wasm code running
        storage.iter_release();

        ret
    }

    fn run_with_input(tx_code: Instance, tx_data: &TxInput) -> Result<()> {
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

#[derive(Clone, Debug)]
pub struct VpRunner {
    wasm_store: wasmer::Store,
}

impl VpRunner {
    pub fn new() -> Self {
        // Use Singlepass compiler with the default settings
        let compiler = wasmer_compiler_singlepass::Singlepass::default();
        let wasm_store =
            wasmer::Store::new(&wasmer_engine_jit::JIT::new(compiler).engine());
        Self { wasm_store }
    }

    pub fn run<T: AsRef<[u8]>>(
        &self,
        vp_code: T,
        tx_data: &Vec<u8>,
        addr: Address,
        storage: &Storage,
        write_log: &WriteLog,
        gas_meter: Arc<Mutex<BlockGasMeter>>,
        keys_changed: &Vec<String>,
    ) -> Result<bool> {
        validate_wasm(vp_code.as_ref())?;

        // This is not thread-safe, we're assuming read-only access from
        // parallel Vp runners.
        let storage = unsafe {
            VpEnvHostWrapper::new(storage as *const _ as *const c_void)
        };
        // This is also not thread-safe, we're assuming read-only access from
        // parallel Vp runners.
        let write_log = unsafe {
            VpEnvHostWrapper::new(write_log as *const _ as *const c_void)
        };

        let vp_code = prepare_wasm_code(vp_code)?;

        let vp_module = wasmer::Module::new(&self.wasm_store, &vp_code)
            .map_err(Error::CompileError)?;
        let initial_memory = memory::prepare_vp_memory(&self.wasm_store)
            .map_err(Error::MemoryError)?;
        let input: VpInput = (addr.to_string(), tx_data, keys_changed);
        let vp_imports = host_env::prepare_vp_imports(
            &self.wasm_store,
            addr,
            storage,
            write_log,
            gas_meter,
            initial_memory,
        );

        // compile and run the transaction wasm code
        let vp_code = wasmer::Instance::new(&vp_module, &vp_imports)
            .map_err(Error::InstantiationError)?;
        VpRunner::run_with_input(vp_code, input)
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
            tx_data_ptr,
            tx_data_len,
            keys_changed_ptr,
            keys_changed_len,
        } = memory::write_vp_inputs(memory, input)
            .map_err(Error::MemoryError)?;

        // Get the module's entrypoint to be called
        let validate_tx = vp_code
            .exports
            .get_function(VP_ENTRYPOINT)
            .map_err(Error::MissingModuleEntrypoint)?
            .native::<(u64, u64, u64, u64, u64, u64), u64>()
            .map_err(|error| Error::UnexpectedModuleEntrypointInterface {
                entrypoint: VP_ENTRYPOINT,
                error,
            })?;
        let is_valid = validate_tx
            .call(
                addr_ptr,
                addr_len,
                tx_data_ptr,
                tx_data_len,
                keys_changed_ptr,
                keys_changed_len,
            )
            .map_err(Error::RuntimeError)?;
        log::debug!("is_valid {}", is_valid);
        Ok(is_valid == 1)
    }
}

#[derive(Clone, Debug)]
pub struct MatchmakerRunner {
    wasm_store: wasmer::Store,
}

impl MatchmakerRunner {
    pub fn new() -> Self {
        // TODO for the matchmaker we could use a compiler that does more
        // optimisation.
        let compiler = wasmer_compiler_singlepass::Singlepass::default();
        let wasm_store =
            wasmer::Store::new(&wasmer_engine_jit::JIT::new(compiler).engine());
        Self { wasm_store }
    }

    pub fn run(
        &self,
        matchmaker_code: impl AsRef<[u8]>,
        intent1_data: impl AsRef<[u8]>,
        intent2_data: impl AsRef<[u8]>,
        tx_code: impl AsRef<[u8]>,
        inject_tx: Sender<Tx>,
    ) -> Result<bool> {
        let matchmaker_module: wasmer::Module =
            wasmer::Module::new(&self.wasm_store, &matchmaker_code)
                .map_err(Error::CompileError)?;
        let initial_memory =
            memory::prepare_matchmaker_memory(&self.wasm_store)
                .map_err(Error::MemoryError)?;

        let matchmaker_imports = host_env::prepare_matchmaker_imports(
            &self.wasm_store,
            initial_memory,
            tx_code,
            inject_tx,
        );

        // compile and run the matchmaker wasm code
        let matchmaker_code =
            wasmer::Instance::new(&matchmaker_module, &matchmaker_imports)
                .map_err(Error::InstantiationError)?;

        Self::run_with_input(&matchmaker_code, intent1_data, intent2_data)
    }

    fn run_with_input(
        code: &Instance,
        intent1_data: impl AsRef<[u8]>,
        intent2_data: impl AsRef<[u8]>,
    ) -> Result<bool> {
        let memory = code
            .exports
            .get_memory("memory")
            .map_err(Error::MissingModuleMemory)?;
        let memory::MatchmakerCallInput {
            intent_data_1_ptr,
            intent_data_1_len,
            intent_data_2_ptr,
            intent_data_2_len,
        }: memory::MatchmakerCallInput = memory::write_matchmaker_inputs(
            &memory,
            intent1_data,
            intent2_data,
        )
        .map_err(Error::MemoryError)?;
        let apply_matchmaker = code
            .exports
            .get_function(MATCHMAKER_ENTRYPOINT)
            .map_err(Error::MissingModuleEntrypoint)?
            .native::<(u64, u64, u64, u64), u64>()
            .map_err(|error| Error::UnexpectedModuleEntrypointInterface {
                entrypoint: MATCHMAKER_ENTRYPOINT,
                error,
            })?;
        let found_match = apply_matchmaker
            .call(
                intent_data_1_ptr,
                intent_data_1_len,
                intent_data_2_ptr,
                intent_data_2_len,
            )
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

fn validate_wasm(wasm_code: &[u8]) -> Result<()> {
    let mut validator = Validator::new();
    let features = WasmFeatures {
        reference_types: false,
        multi_value: false,
        bulk_memory: false,
        module_linking: false,
        simd: false,
        threads: false,
        tail_call: false,
        deterministic_only: true,
        multi_memory: false,
        exceptions: false,
        memory64: false,
    };
    validator.wasm_features(features);

    validator
        .validate_all(wasm_code)
        .map_err(Error::ValidationError)
}

#[cfg(test)]
mod tests {
    use tempdir::TempDir;
    use wasmer_vm;

    use super::*;
    use crate::shell::storage::ValidatorAddress;

    /// Test that when a transaction wasm goes over the stack-height limit, the
    /// execution is aborted.
    #[test]
    fn test_tx_stack_limiter() {
        // Because each call into `$loop` inside the wasm consumes 4 stack
        // heights, this should trigger stack limiter. If we were to subtract
        // one from this value, we should be just under the limit.
        let loops = WASM_STACK_LIMIT / 4;
        // A transaction with a recursive loop.
        // The boilerplate code is generated from tx.wasm using `wasm2wat` and
        // the loop code is hand-written.
        let tx_code = wasmer::wat2wasm(
            format!(
                r#"
            (module
                (type (;0;) (func (param i64 i64) (result i64)))

                ;; recursive loop, the param is the number of loops
                (func $loop (param i64) (result i64)
                (if
                (result i64)
                (i64.eqz (get_local 0))
                (then (get_local 0))
                (else (call $loop (i64.sub (get_local 0) (i64.const 1))))))

                (func $apply_tx (type 0) (param i64 i64) (result i64)
                (call $loop (i64.const {})))

                (table (;0;) 1 1 funcref)
                (memory (;0;) 16)
                (global (;0;) (mut i32) (i32.const 1048576))
                (export "memory" (memory 0))
                (export "apply_tx" (func $apply_tx)))
            "#,
                loops
            )
            .as_bytes(),
        )
        .expect("unexpected error converting wat2wasm")
        .into_owned();

        let runner = TxRunner::new();
        let tx_data = vec![];
        let db_path = TempDir::new("anoma_test")
            .expect("Unable to create a temporary DB directory");
        let mut storage = Storage::new(db_path.path());
        let mut write_log = WriteLog::new();
        let mut gas_meter = BlockGasMeter::default();
        let error = runner
            .run(
                &mut storage,
                &mut write_log,
                &mut gas_meter,
                tx_code,
                &tx_data,
            )
            .expect_err(
                "Expecting runtime error \"unreachable\" caused by \
                 stack-height overflow",
            );
        if let Error::RuntimeError(err) = &error {
            if let Some(trap_code) = err.clone().to_trap() {
                return assert_eq!(
                    trap_code,
                    wasmer_vm::TrapCode::UnreachableCodeReached
                );
            }
        }
        println!("Failed with unexpected error: {}", error);
    }

    /// Test that when a VP wasm goes over the stack-height limit, the execution
    /// is aborted.
    #[test]
    fn test_vp_stack_limiter() {
        // Because each call into `$loop` inside the wasm consumes 4 stack
        // heights, this should trigger stack limiter. If we were to subtract
        // one from this value, we should be just under the limit.
        let loops = WASM_STACK_LIMIT / 4;
        // A validity predicate with a recursive loop.
        // The boilerplate code is generated from vp.wasm using `wasm2wat` and
        // the loop code is hand-written.
        let vp_code = wasmer::wat2wasm(format!(
            r#"
            (module
                (type (;0;) (func (param i64 i64 i64 i64 i64 i64) (result i64)))

                ;; recursive loop, the param is the number of loops
                (func $loop (param i64) (result i64)
                (if
                (result i64)
                (i64.eqz (get_local 0))
                (then (get_local 0))
                (else (call $loop (i64.sub (get_local 0) (i64.const 1))))))

                (func $validate_tx (type 0) (param i64 i64 i64 i64 i64 i64) (result i64)
                (call $loop (i64.const {})))

                (table (;0;) 1 1 funcref)
                (memory (;0;) 16)
                (global (;0;) (mut i32) (i32.const 1048576))
                (export "memory" (memory 0))
                (export "validate_tx" (func $validate_tx)))
            "#, loops).as_bytes(),
        )
        .expect("unexpected error converting wat2wasm").into_owned();

        let runner = VpRunner::new();
        let tx_data = vec![];
        let addr = Address::Validator(ValidatorAddress("va".into()));
        let db_path = TempDir::new("anoma_test")
            .expect("Unable to create a temporary DB directory");
        let storage = Storage::new(db_path.path());
        let write_log = WriteLog::new();
        let gas_meter = Arc::new(Mutex::new(BlockGasMeter::default()));
        let keys_changed = vec![];
        let error = runner
            .run(
                vp_code,
                &tx_data,
                addr,
                &storage,
                &write_log,
                gas_meter,
                &keys_changed,
            )
            .expect_err(
                "Expecting runtime error \"unreachable\" caused by \
                 stack-height overflow",
            );
        if let Error::RuntimeError(err) = &error {
            if let Some(trap_code) = err.clone().to_trap() {
                return assert_eq!(
                    trap_code,
                    wasmer_vm::TrapCode::UnreachableCodeReached
                );
            }
        }
        println!("Failed with unexpected error: {}", error);
    }
}
