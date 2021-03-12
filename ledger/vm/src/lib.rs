use borsh::{BorshDeserialize, BorshSerialize};
use std::{
    io::Write,
    sync::{mpsc, Arc, Mutex},
};
use thiserror::Error;
use wasmer::{
    internals::WithEnv, HostEnvInitError, HostFunction, Instance, Memory,
    WasmerEnv,
};

const TX_ENTRYPOINT: &str = "apply_tx";
const VP_ENTRYPOINT: &str = "validate_tx";

// #[derive(wasmer::WasmerEnv, Clone)]
#[derive(Clone)]
pub struct TxEnv {
    // TODO Mutex is not great, we only ever read, but it's what WasmerEnv
    // currently implements. There must be a better way...
    pub sender: Arc<Mutex<mpsc::Sender<TxMsg>>>,
    // #[wasmer(export)]
    pub memory: wasmer::LazyInit<Memory>,
}

impl WasmerEnv for TxEnv {
    fn init_with_instance(
        &mut self,
        instance: &Instance,
    ) -> std::result::Result<(), HostEnvInitError> {
        let memory = instance.exports.get_memory("memory")?;
        self.memory.initialize(memory.clone());
        Ok(())
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct TxMsg {
    pub src: String,
    pub dest: String,
    pub amount: u64,
}

#[derive(Clone, Debug)]
pub struct TxRunner {
    wasm_store: wasmer::Store,
}

#[derive(Error, Debug)]
pub enum Error {
    // 1. Common error types
    #[error("Failed initializing the memory {0}")]
    InitMemoryError(wasmer::MemoryError),
    #[error("Failed initializing the memory {0}")]
    MemoryExportError(wasmer::ExportError),
    // 2. Transaction errors
    #[error("Transaction compilation error {0}")]
    TxCompileError(wasmer::CompileError),
    #[error("Validity predicate compilation error {0}")]
    MissingTxModuleEntrypoint(wasmer::ExportError),
    #[error("Unexpected transaction module entrypoint interface {TX_ENTRYPOINT}, failed with {0}")]
    UnexpectedTxModuleEntrypointInterface(wasmer::RuntimeError),
    #[error("Failed running transaction with {0}")]
    TxRuntimeError(wasmer::RuntimeError),
    #[error("Failed instantiating transaction module with {0}")]
    TxInstantiationError(wasmer::InstantiationError),
    #[error("Missing validity predicate entrypoint {VP_ENTRYPOINT}, failed with {0}")]
    // 3. Validity predicate errors
    VpCompileError(wasmer::CompileError),
    #[error("Missing transaction entrypoint {TX_ENTRYPOINT}, failed with {0}")]
    MissingVpModuleEntrypoint(wasmer::ExportError),
    #[error("Unexpected validity predicate module entrypoint interface {VP_ENTRYPOINT}, failed with {0}")]
    UnexpectedVpModuleEntrypointInterface(wasmer::RuntimeError),
    #[error("Failed running validity predicate with {0}")]
    VpRuntimeError(wasmer::RuntimeError),
    #[error("Failed instantiating validity predicate module with {0}")]
    VpInstantiationError(wasmer::InstantiationError),
    #[error("Validity predicate failed to send result {0}")]
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

    pub fn run<F>(
        &self,
        tx_code: Vec<u8>,
        tx_data: Vec<u8>,
        tx_sender: mpsc::Sender<TxMsg>,
        transfer: F,
    ) -> Result<()>
    where
        F: HostFunction<(i32, i32, i32, i32, u64), (), WithEnv, TxEnv>,
    {
        let tx_env = TxEnv {
            sender: Arc::new(Mutex::new(tx_sender)),
            memory: wasmer::LazyInit::default(),
        };
        let tx_module = wasmer::Module::new(&self.wasm_store, &tx_code)
            .map_err(|e| Error::TxCompileError(e))?;
        let memory = Memory::new(
            &self.wasm_store,
            wasmer::MemoryType::new(1, None, false),
        )
        .map_err(|e| Error::InitMemoryError(e).into())?;
        let tx_imports = wasmer::imports! {
            // default namespace
            "env" => {
                "memory" => memory,
                "transfer" => wasmer::Function::new_native_with_env(&self.wasm_store, tx_env, transfer),
            },
        };
        // compile and run the transaction wasm code
        let tx_code = wasmer::Instance::new(&tx_module, &tx_imports)
            .map_err(|e| Error::TxInstantiationError(e).into())?;
        let apply_tx = tx_code
            .exports
            .get_function(TX_ENTRYPOINT)
            .map_err(|e| Error::MissingTxModuleEntrypoint(e).into())?
            .native::<(i32, i32), ()>()
            .map_err(|e| {
                Error::UnexpectedTxModuleEntrypointInterface(e).into()
            })?;
        apply_tx
            .call(tx_data.as_ptr() as i32, tx_data.len() as i32)
            .map_err(|e| Error::TxRuntimeError(e).into())?;
        Ok(())
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
        tx_msg: &TxMsg,
        vp_sender: mpsc::Sender<VpMsg>,
    ) -> Result<()> {
        let vp_module = wasmer::Module::new(&self.wasm_store, &vp_code)
            .map_err(|e| Error::TxCompileError(e))?;
        let mut tx_bytes = Vec::with_capacity(1024);
        tx_msg.serialize(&mut tx_bytes).expect("TEMPORARY: failed to serialize TxMsg for validity predicate - this will be handled in memory module");

        let memory = Memory::new(
            &self.wasm_store,
            wasmer::MemoryType::new(1, None, false),
        )
        .map_err(|e| Error::InitMemoryError(e).into())?;
        let vp_imports = wasmer::imports! {
            // default namespace
            "env" => {
                "memory" => memory,
            },
        };
        // compile and run the transaction wasm code
        let vp_code = wasmer::Instance::new(&vp_module, &vp_imports)
            .map_err(|e| Error::VpInstantiationError(e).into())?;
        let memory = vp_code
            .exports
            .get_memory("memory")
            .map_err(|e| Error::MemoryExportError(e).into())?;
        {
            // TODO: do this safely in a customized memory implementation
            let mut data = unsafe { memory.data_unchecked_mut() };
            // NOTE: the memory is initialized with 1 page (64kb in
            // `wasmer::Pages`), so this data fits in
            data.write(&tx_bytes).expect("TEMPORARY: failed to write TxMsg for validity predicate - this will be handled in memory module");
        }

        let validate_tx = vp_code
            .exports
            .get_function(VP_ENTRYPOINT)
            .map_err(|e| Error::MissingVpModuleEntrypoint(e).into())?
            .native::<(i32, i32), i32>()
            .map_err(|e| {
                Error::UnexpectedVpModuleEntrypointInterface(e).into()
            })?;
        let is_valid = validate_tx
            // TODO: we use 0 for the tx_bytes pointer, because we wrote the
            // `tx_bytes` in the front of `memory`, this should be handled in
            // the memory implementation
            .call(0 as i32, tx_bytes.len() as i32)
            .map_err(|e| Error::VpRuntimeError(e).into())?
            == 1;
        vp_sender
            .send(is_valid)
            .map_err(|e| Error::VpChannelError(e))?;
        Ok(())
    }
}
