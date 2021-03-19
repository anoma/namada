mod memory;
pub mod types;

use anoma_vm_env::memory::WriteLog;
use memory::AnomaMemory;
use std::ffi::c_void;
use std::sync::{mpsc, Arc, Mutex};
use thiserror::Error;
use wasmer::{
    internals::WithEnv, HostEnvInitError, HostFunction, Instance, WasmPtr,
    WasmerEnv,
};

#[derive(Clone)]
pub struct LedgerWrapper(pub *mut c_void);
unsafe impl Send for LedgerWrapper {}
unsafe impl Sync for LedgerWrapper {}

const TX_ENTRYPOINT: &str = "apply_tx";
const VP_ENTRYPOINT: &str = "validate_tx";

// TODO check WasmerEnv issue
// #[derive(wasmer::WasmerEnv, Clone)]
#[derive(Clone)]
pub struct TxEnv {
    // // TODO Mutex is not great, we only ever read, but it's what WasmerEnv
    // // currently implements. There must be a better way...
    // pub sender: Arc<Mutex<mpsc::Sender<TxRequest>>>,
    // not thread-safe, assuming single-theaded Tx runner
    pub ledger: LedgerWrapper,
    // #[wasmer(export)]
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

    pub fn run<Read, Update>(
        &self,
        ledger: LedgerWrapper,
        tx_code: Vec<u8>,
        tx_data: &Vec<u8>,
        storage_read: Read,
        storage_update: Update,
    ) -> Result<()>
    where
        Read: HostFunction<(i32, i32, u64), i32, WithEnv, TxEnv>,
        Update: HostFunction<(i32, i32, i32, i32), (), WithEnv, TxEnv>,
    {
        let tx_env = TxEnv {
            ledger,
            memory: AnomaMemory::default(),
        };
        let tx_module = wasmer::Module::new(&self.wasm_store, &tx_code)
            .map_err(Error::TxCompileError)?;
        let memory = memory::prepare_tx_memory(&self.wasm_store)
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

        self.run_with_input(tx_code, tx_data)?;
        Ok(())
    }

    fn run_with_input(
        &self,
        tx_code: Instance,
        tx_data: &Vec<u8>,
    ) -> Result<()> {
        let memory::TxCallInput {
            tx_data_ptr,
            tx_data_len,
        }: memory::TxCallInput =
            memory::write_tx_inputs(&tx_code.exports, tx_data)
                .map_err(Error::MemoryError)?;
        let apply_tx = tx_code
            .exports
            .get_function(TX_ENTRYPOINT)
            .map_err(Error::MissingTxModuleEntrypoint)?
            .native::<(i32, i32), ()>()
            .map_err(Error::UnexpectedTxModuleEntrypointInterface)?;
        apply_tx
            .call(tx_data_ptr, tx_data_len)
            .map_err(Error::TxRuntimeError)
    }
}
// #[derive(wasmer::WasmerEnv, Clone)]
#[derive(Clone)]
pub struct VpEnv {
    pub ledger: LedgerWrapper,
    // #[wasmer(export)]
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
        // TODO Could we pass the modified accounts sub-spaces via WASM store
        // directly to VPs' wasm scripts to avoid passing it through the
        // host?
        let wasm_store =
            wasmer::Store::new(&wasmer_engine_jit::JIT::new(compiler).engine());
        Self { wasm_store }
    }

    pub fn run(
        &self,
        vp_code: impl AsRef<[u8]>,
        tx_data: &Vec<u8>,
        write_log: &WriteLog,
        vp_sender: mpsc::Sender<VpMsg>,
    ) -> Result<()> {
        let vp_module = wasmer::Module::new(&self.wasm_store, &vp_code)
            .map_err(Error::TxCompileError)?;

        let memory = memory::prepare_vp_memory(&self.wasm_store)
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

        let is_valid = self.run_with_input(vp_code, tx_data, write_log)?;
        vp_sender
            .send(is_valid)
            .map_err(|e| Error::VpChannelError(e))?;
        Ok(())
    }

    fn run_with_input(
        &self,
        vp_code: Instance,
        tx_data: &Vec<u8>,
        write_log: &Vec<anoma_vm_env::StorageUpdate>,
    ) -> Result<bool> {
        // TODO this can be nicer
        let inputs = (tx_data, write_log);
        let memory::VpCallInput {
            tx_data_ptr,
            tx_data_len,
            write_log_ptr,
            write_log_len,
        } = memory::write_vp_inputs(&vp_code.exports, inputs)
            .map_err(Error::MemoryError)?;

        let validate_tx = vp_code
            .exports
            .get_function(VP_ENTRYPOINT)
            .map_err(Error::MissingVpModuleEntrypoint)?
            .native::<(i32, i32, i32, i32), i32>()
            .map_err(Error::UnexpectedVpModuleEntrypointInterface)?;
        let is_valid = validate_tx
            .call(tx_data_ptr, tx_data_len, write_log_ptr, write_log_len)
            .map_err(Error::VpRuntimeError)?;
        Ok(is_valid == 1)
    }
}
