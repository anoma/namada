pub mod host_env;
mod memory;

use std::sync::mpsc;
use std::{ffi::c_void, marker::PhantomData};

use anoma_vm_env::memory::VpInput;
use thiserror::Error;
use wasmer::Instance;

use crate::shell::storage::Storage;

use self::host_env::write_log::WriteLog;

const TX_ENTRYPOINT: &str = "apply_tx";
const VP_ENTRYPOINT: &str = "validate_tx";

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
    /// This is not thread-safe, see [`VmEnvHostWrapper`]
    unsafe fn new(host_structure: *mut c_void) -> Self {
        Self(host_structure, PhantomData)
    }

    /// This is not thread-safe, see [`VmEnvHostWrapper`]
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
    /// This is not thread-safe, see [`VmEnvHostWrapper`]
    unsafe fn new(host_structure: *const c_void) -> Self {
        Self(host_structure, PhantomData)
    }

    /// This is not thread-safe, see [`VmEnvHostWrapper`]
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
    #[error(
        "Missing validity predicate entrypoint {VP_ENTRYPOINT}, failed with: \
         {0}"
    )]
    // 3. Validity predicate errors
    VpCompileError(wasmer::CompileError),
    #[error(
        "Missing transaction entrypoint {TX_ENTRYPOINT}, failed with: {0}"
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
        let call_input = memory::write_tx_inputs(&initial_memory, tx_data)
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
        storage: &Storage,
        write_log: &WriteLog,
        keys_changed: &Vec<String>,
        vp_sender: mpsc::Sender<VpMsg>,
    ) -> Result<()> {
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
        let input: VpInput = (addr, tx_data, keys_changed);
        let call_input = memory::write_vp_inputs(&initial_memory, input)
            .map_err(Error::MemoryError)?;
        let vp_imports = host_env::prepare_vp_imports(
            &self.wasm_store,
            storage,
            write_log,
            initial_memory,
        );

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
            keys_changed_ptr,
            keys_changed_len,
        }: memory::VpCallInput,
    ) -> Result<bool> {
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
