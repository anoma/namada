mod memory;

use anoma_vm_env::memory::{VpInput, WriteLog};
use memory::AnomaMemory;
use std::ffi::c_void;
use std::sync::mpsc;
use thiserror::Error;
use wasmer::{
    internals::WithEnv, HostEnvInitError, HostFunction, Instance, WasmerEnv,
};

/// This is used to attach the Ledger's shell to transaction environment,
/// which is used for implementing some host calls.
/// It's not thread-safe, we're assuming single-threaded Tx runner.
#[derive(Clone)]
pub struct TxShellWrapper(*mut c_void);
unsafe impl Send for TxShellWrapper {}
unsafe impl Sync for TxShellWrapper {}

impl TxShellWrapper {
    /// This is not thread-safe, we're assuming single-threaded Tx runner.
    pub unsafe fn new(ledger: *mut c_void) -> Self {
        Self(ledger)
    }

    /// This is not thread-safe, we're assuming single-threaded Tx runner.
    pub unsafe fn get(&self) -> *mut c_void {
        self.0
    }
}

const TX_ENTRYPOINT: &str = "apply_tx";
const VP_ENTRYPOINT: &str = "validate_tx";

#[derive(Clone)]
pub struct TxEnv {
    // not thread-safe, assuming single-threaded Tx runner
    pub ledger: TxShellWrapper,
    pub memory: AnomaMemory,
}

impl WasmerEnv for TxEnv {
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
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
    // 2. Transaction errors
    #[error("Transaction compilation error: {0}")]
    TxCompileError(wasmer::CompileError),
    #[error("Validity predicate compilation error: {0}")]
    MissingTxModuleEntrypoint(wasmer::ExportError),
    #[error("Unexpected transaction module entrypoint interface {TX_ENTRYPOINT}, failed with: {0}")]
    UnexpectedTxModuleEntrypointInterface(wasmer::RuntimeError),
    #[error("Failed running transaction with: {0}")]
    TxRuntimeError(wasmer::RuntimeError),
    #[error("Failed instantiating transaction module with: {0}")]
    TxInstantiationError(wasmer::InstantiationError),
    #[error("Missing validity predicate entrypoint {VP_ENTRYPOINT}, failed with: {0}")]
    // 3. Validity predicate errors
    VpCompileError(wasmer::CompileError),
    #[error(
        "Missing transaction entrypoint {TX_ENTRYPOINT}, failed with: {0}"
    )]
    MissingVpModuleEntrypoint(wasmer::ExportError),
    #[error("Unexpected validity predicate module entrypoint interface {VP_ENTRYPOINT}, failed with: {0}")]
    UnexpectedVpModuleEntrypointInterface(wasmer::RuntimeError),
    #[error("Failed running validity predicate with: {0}")]
    VpRuntimeError(wasmer::RuntimeError),
    #[error("Failed instantiating validity predicate module with: {0}")]
    VpInstantiationError(wasmer::InstantiationError),
    #[error("Validity predicate failed to send result: {0}")]
    VpChannelError(mpsc::SendError<bool>),
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

    pub fn run<Read, Write>(
        &self,
        ledger: TxShellWrapper,
        tx_code: Vec<u8>,
        tx_data: &Vec<u8>,
        storage_read: Read,
        storage_update: Write,
    ) -> Result<()>
    where
        Read: HostFunction<(u64, u64, u64), u64, WithEnv, TxEnv>,
        Write: HostFunction<(u64, u64, u64, u64), u64, WithEnv, TxEnv>,
    {
        let tx_env = TxEnv {
            ledger,
            memory: AnomaMemory::default(),
        };
        let tx_module = wasmer::Module::new(&self.wasm_store, &tx_code)
            .map_err(Error::TxCompileError)?;
        let memory = memory::prepare_tx_memory(&self.wasm_store)
            .map_err(Error::MemoryError)?;
        let call_input = memory::write_tx_inputs(&memory, tx_data)
            .map_err(Error::MemoryError)?;
        let tx_imports = wasmer::imports! {
            // default namespace
            "env" => {
                "memory" => memory,
                "read" => wasmer::Function::new_native_with_env(&self.wasm_store, tx_env.clone(), storage_read),
                "update" => wasmer::Function::new_native_with_env(&self.wasm_store, tx_env, storage_update),
            },
        };
        // compile and run the transaction wasm code
        let tx_code = wasmer::Instance::new(&tx_module, &tx_imports)
            .map_err(Error::TxInstantiationError)?;

        self.run_with_input(tx_code, call_input)?;
        Ok(())
    }

    fn run_with_input(
        &self,
        tx_code: Instance,
        memory::TxCallInput {
            tx_data_ptr,
            tx_data_len,
        }: memory::TxCallInput,
    ) -> Result<()> {
        let apply_tx = tx_code
            .exports
            .get_function(TX_ENTRYPOINT)
            .map_err(Error::MissingTxModuleEntrypoint)?
            .native::<(u64, u64), ()>()
            .map_err(Error::UnexpectedTxModuleEntrypointInterface)?;
        apply_tx
            .call(tx_data_ptr, tx_data_len)
            .map_err(Error::TxRuntimeError)
    }
}

#[derive(Clone)]
pub struct VpEnv {
    pub ledger: TxShellWrapper,
    pub memory: AnomaMemory,
}

impl WasmerEnv for VpEnv {
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        self.memory.init_env_memory(&instance.exports)
    }
}

// does the validity predicate accept the state changes?
pub type VpMsg = bool;

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

    pub fn run(
        &self,
        vp_code: impl AsRef<[u8]>,
        tx_data: &Vec<u8>,
        addr: String,
        write_log: &WriteLog,
        vp_sender: mpsc::Sender<VpMsg>,
    ) -> Result<()> {
        let vp_module = wasmer::Module::new(&self.wasm_store, &vp_code)
            .map_err(Error::TxCompileError)?;

        let memory = memory::prepare_vp_memory(&self.wasm_store)
            .map_err(Error::MemoryError)?;
        let input: VpInput = (addr, tx_data, write_log);
        let call_input = memory::write_vp_inputs(&memory, input)
            .map_err(Error::MemoryError)?;
        let vp_imports = wasmer::imports! {
            // default namespace
            "env" => {
                "memory" => memory,
            },
        };
        // compile and run the transaction wasm code
        let vp_code = wasmer::Instance::new(&vp_module, &vp_imports)
            .map_err(Error::VpInstantiationError)?;

        let is_valid = self.run_with_input(vp_code, call_input)?;

        vp_sender
            .send(is_valid)
            .map_err(|e| Error::VpChannelError(e))?;
        Ok(())
    }

    fn run_with_input(
        &self,
        vp_code: Instance,
        memory::VpCallInput {
            addr_ptr,
            addr_len,
            tx_data_ptr,
            tx_data_len,
            write_log_ptr,
            write_log_len,
        }: memory::VpCallInput,
    ) -> Result<bool> {
        let validate_tx = vp_code
            .exports
            .get_function(VP_ENTRYPOINT)
            .map_err(Error::MissingVpModuleEntrypoint)?
            .native::<(u64, u64, u64, u64, u64, u64), u64>()
            .map_err(Error::UnexpectedVpModuleEntrypointInterface)?;
        let input = memory::VpCallInput {
            addr_ptr,
            addr_len,
            tx_data_ptr,
            tx_data_len,
            write_log_ptr,
            write_log_len,
        };
        println!("run VP input {:#?}", input);
        let is_valid = validate_tx
            .call(
                addr_ptr,
                addr_len,
                tx_data_ptr,
                tx_data_len,
                write_log_ptr,
                write_log_len,
            )
            .map_err(Error::VpRuntimeError)?;
        Ok(is_valid == 1)
    }
}
