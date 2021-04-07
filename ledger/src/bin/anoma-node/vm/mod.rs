pub mod host_env;
mod memory;

use std::ffi::c_void;
use std::marker::PhantomData;

use anoma::protobuf::types::Tx;
use anoma_vm_env::memory::{TxInput, VpInput};
use thiserror::Error;
use tokio::sync::mpsc::Sender;
use wasmer::Instance;

use self::host_env::write_log::WriteLog;
use crate::shell::storage::{Address, Storage};

const TX_ENTRYPOINT: &str = "apply_tx";
const VP_ENTRYPOINT: &str = "validate_tx";
const MATCHMAKER_ENTRYPOINT: &str = "match_intent";

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
    // 2. Transaction errors
    #[error("Transaction compilation error: {0}")]
    TxCompileError(wasmer::CompileError),
    #[error("Missing transaction memory export, failed with: {0}")]
    MissingTxModuleMemory(wasmer::ExportError),
    #[error("Validity predicate compilation error: {0}")]
    MissingTxModuleEntrypoint(wasmer::ExportError),
    #[error(
        "Unexpected transaction module entrypoint interface {TX_ENTRYPOINT}, \
         failed with: {0}"
    )]
    UnexpectedTxModuleEntrypointInterface(wasmer::RuntimeError),
    #[error("Failed running transaction with: {0}")]
    TxRuntimeError(wasmer::RuntimeError),
    #[error("Failed instantiating transaction module with: {0}")]
    TxInstantiationError(wasmer::InstantiationError),
    // 3. Validity predicate errors
    #[error(
        "Missing validity predicate entrypoint {VP_ENTRYPOINT}, failed with: \
         {0}"
    )]
    VpCompileError(wasmer::CompileError),
    #[error("Missing validity predicate memory export, failed with: {0}")]
    MissingVpModuleMemory(wasmer::ExportError),
    #[error(
        "Missing validity predicate entrypoint {TX_ENTRYPOINT}, failed with: \
         {0}"
    )]
    MissingVpModuleEntrypoint(wasmer::ExportError),
    #[error(
        "Unexpected validity predicate module entrypoint interface \
         {VP_ENTRYPOINT}, failed with: {0}"
    )]
    UnexpectedVpModuleEntrypointInterface(wasmer::RuntimeError),
    #[error("Failed running validity predicate with: {0}")]
    VpRuntimeError(wasmer::RuntimeError),
    #[error("Failed instantiating validity predicate module with: {0}")]
    VpInstantiationError(wasmer::InstantiationError),
    // 4. Matchmaker predicate error
    #[error("matchmaker compilation error: {0}")]
    MatchmakerCompileError(wasmer::CompileError),
    #[error(
        "Unexpected matchmaker module entrypoint interface \
         {MATCHMAKER_ENTRYPOINT}, failed with: {0}"
    )]
    UnexpectedMatchmakerModuleEntrypointInterface(wasmer::RuntimeError),
    #[error("Missing matchmaker memory export, failed with: {0}")]
    MissingMatchmakerModuleMemory(wasmer::ExportError),
    #[error("Failed running matchmaker with: {0}")]
    MatchmakerRuntimeError(wasmer::RuntimeError),
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
        tx_code: Vec<u8>,
        tx_data: &Vec<u8>,
    ) -> Result<()> {
        // This is not thread-safe, we're assuming single-threaded Tx runner.
        let storage =
            unsafe { TxEnvHostWrapper::new(storage as *mut _ as *mut c_void) };
        // This is also not thread-safe, we're assuming single-threaded Tx
        // runner.
        let write_log = unsafe {
            TxEnvHostWrapper::new(write_log as *mut _ as *mut c_void)
        };

        let tx_module = wasmer::Module::new(&self.wasm_store, &tx_code)
            .map_err(Error::TxCompileError)?;
        let initial_memory = memory::prepare_tx_memory(&self.wasm_store)
            .map_err(Error::MemoryError)?;
        let tx_imports = host_env::prepare_tx_imports(
            &self.wasm_store,
            storage,
            write_log,
            initial_memory,
        );

        // compile and run the transaction wasm code
        let tx_code = wasmer::Instance::new(&tx_module, &tx_imports)
            .map_err(Error::TxInstantiationError)?;
        self.run_with_input(tx_code, tx_data)
    }

    fn run_with_input(
        &self,
        tx_code: Instance,
        tx_data: &TxInput,
    ) -> Result<()> {
        // We need to write the inputs in the memory exported from the wasm
        // module
        let memory = tx_code
            .exports
            .get_memory("memory")
            .map_err(Error::MissingTxModuleMemory)?;
        let memory::TxCallInput {
            tx_data_ptr,
            tx_data_len,
        } = memory::write_tx_inputs(memory, tx_data)
            .map_err(Error::MemoryError)?;

        // Get the module's entrypoint to be called
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
        addr: Address,
        storage: &Storage,
        write_log: &WriteLog,
        keys_changed: &Vec<String>,
    ) -> Result<bool> {
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

        let vp_module = wasmer::Module::new(&self.wasm_store, &vp_code)
            .map_err(Error::VpCompileError)?;
        let initial_memory = memory::prepare_vp_memory(&self.wasm_store)
            .map_err(Error::MemoryError)?;
        let input: VpInput = (addr.to_string(), tx_data, keys_changed);
        let vp_imports = host_env::prepare_vp_imports(
            &self.wasm_store,
            addr,
            storage,
            write_log,
            initial_memory,
        );

        // compile and run the transaction wasm code
        let vp_code = wasmer::Instance::new(&vp_module, &vp_imports)
            .map_err(Error::VpInstantiationError)?;
        self.run_with_input(vp_code, input)
    }

    fn run_with_input(
        &self,
        vp_code: Instance,
        input: VpInput,
    ) -> Result<bool> {
        // We need to write the inputs in the memory exported from the wasm
        // module
        let memory = vp_code
            .exports
            .get_memory("memory")
            .map_err(Error::MissingVpModuleMemory)?;
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
            .map_err(Error::MissingVpModuleEntrypoint)?
            .native::<(u64, u64, u64, u64, u64, u64), u64>()
            .map_err(Error::UnexpectedVpModuleEntrypointInterface)?;
        let is_valid = validate_tx
            .call(
                addr_ptr,
                addr_len,
                tx_data_ptr,
                tx_data_len,
                keys_changed_ptr,
                keys_changed_len,
            )
            .map_err(Error::VpRuntimeError)?;
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
        // ledger: TxShellWrapper,
        matchmaker_code: impl AsRef<[u8]>,
        intent1_data: impl AsRef<[u8]>,
        intent2_data: impl AsRef<[u8]>,
        tx_code: impl AsRef<[u8]>,
        inject_tx: Sender<Tx>,
    ) -> Result<bool> {
        let matchmaker_module: wasmer::Module =
            wasmer::Module::new(&self.wasm_store, &matchmaker_code)
                .map_err(Error::MatchmakerCompileError)?;
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
                .map_err(Error::TxInstantiationError)?;

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
            .map_err(Error::MissingMatchmakerModuleMemory)?;
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
        println!("running matchmaker");
        let apply_matchmaker = code
            .exports
            .get_function(MATCHMAKER_ENTRYPOINT)
            .map_err(Error::MissingTxModuleEntrypoint)?
            .native::<(u64, u64, u64, u64), u64>()
            .map_err(Error::UnexpectedMatchmakerModuleEntrypointInterface)?;
        println!("running matchmaker2");
        let found_match = apply_matchmaker
            .call(
                intent_data_1_ptr,
                intent_data_1_len,
                intent_data_2_ptr,
                intent_data_2_len,
            )
            .map_err(Error::MatchmakerRuntimeError)?;
        println!("running matchmaker3 {}", found_match);
        Ok(found_match == 0)
    }
}
