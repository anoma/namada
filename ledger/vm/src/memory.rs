use anoma_vm_env::memory;
use borsh::BorshSerialize;
use std::io::{IoSlice, Write};
use thiserror::Error;
use wasmer::{HostEnvInitError, LazyInit, Memory};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed initializing the memory: {0}")]
    InitMemoryError(wasmer::MemoryError),
    #[error("Failed exporting the memory: {0}")]
    MemoryExportError(wasmer::ExportError),
    #[error("Memory is not initialized")]
    UninitializedMemory,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Prepare memory for instantiating a transaction module
pub fn prepare_tx_memory(store: &wasmer::Store) -> Result<wasmer::Memory> {
    let mem_type = wasmer::MemoryType::new(1, None, false);
    Memory::new(store, mem_type).map_err(Error::InitMemoryError)
}

/// Prepare memory for instantiating a validity predicate module
pub fn prepare_vp_memory(store: &wasmer::Store) -> Result<wasmer::Memory> {
    let mem_type = wasmer::MemoryType::new(1, None, false);
    Memory::new(store, mem_type).map_err(Error::InitMemoryError)
}

pub struct TxCallInput {
    pub tx_data_ptr: u64,
    pub tx_data_len: u64,
}

pub fn write_tx_inputs(
    exports: &wasmer::Exports,
    tx_data_bytes: &memory::TxData,
) -> Result<TxCallInput> {
    let memory = exports
        .get_memory("memory")
        .map_err(Error::MemoryExportError)?;

    let tx_data_ptr = 0;
    let tx_data_len = tx_data_bytes.len() as _;

    // TODO check size and grow memory if needed
    let mut data = unsafe { memory.data_unchecked_mut() };
    data.write(tx_data_bytes)
        .expect("TEMPORARY: failed to write tx_data for transaction");

    Ok(TxCallInput {
        tx_data_ptr,
        tx_data_len,
    })
}

pub struct VpCallInput {
    pub addr_ptr: u64,
    pub addr_len: u64,
    pub tx_data_ptr: u64,
    pub tx_data_len: u64,
    pub write_log_ptr: u64,
    pub write_log_len: u64,
}

pub fn write_vp_inputs(
    exports: &wasmer::Exports,
    (addr, tx_data_bytes, write_log): memory::VpInput,
) -> Result<VpCallInput> {
    let memory = exports
        .get_memory("memory")
        .map_err(Error::MemoryExportError)?;

    let addr_ptr = 0;
    let mut addr_bytes = Vec::with_capacity(1024);
    addr.serialize(&mut addr_bytes)
        .expect("TEMPORARY: failed to serialize addr for validity predicate");
    let addr_len = addr_bytes.len() as _;

    let tx_data_ptr = addr_ptr + addr_len;
    let tx_data_len = tx_data_bytes.len() as _;

    let mut write_log_bytes = Vec::with_capacity(1024);
    write_log.serialize(&mut write_log_bytes).expect(
        "TEMPORARY: failed to serialize write_log for validity predicate",
    );
    let write_log_ptr = tx_data_ptr + tx_data_len;
    let write_log_len = write_log_bytes.len() as _;

    // TODO check size and grow memory if needed
    let mut data = unsafe { memory.data_unchecked_mut() };
    let bufs = [IoSlice::new(tx_data_bytes), IoSlice::new(&write_log_bytes)];
    data.write_vectored(&bufs)
        .expect("TEMPORARY: failed to write inputs for validity predicate");

    Ok(VpCallInput {
        addr_ptr,
        addr_len,
        tx_data_ptr,
        tx_data_len,
        write_log_ptr,
        write_log_len,
    })
}

#[derive(Debug, Clone)]
pub struct AnomaMemory {
    inner: LazyInit<wasmer::Memory>,
}
impl AnomaMemory {
    /// Initialize the memory from the given exports
    pub fn init_env_memory(
        &mut self,
        exports: &wasmer::Exports,
    ) -> std::result::Result<(), HostEnvInitError> {
        let memory = exports.get_memory("memory")?;
        if !self.inner.initialize(memory.clone()) {
            log::error!("wasm memory is already initialized");
        }
        Ok(())
    }

    pub fn read_string(&self, str_ptr: u64, str_len: u64) -> Result<String> {
        let memory = self.inner.get_ref().ok_or(Error::UninitializedMemory)?;
        let str_vec: Vec<_> = memory.view()
            [str_ptr as usize..(str_ptr + str_len) as usize]
            .iter()
            .map(|cell| cell.get())
            .collect();
        Ok(std::str::from_utf8(&str_vec)
            .expect("unable to read string from memory")
            .to_string())
    }

    pub fn read_bytes(&self, ptr: u64, len: u64) -> Result<Vec<u8>> {
        let memory = self.inner.get_ref().ok_or(Error::UninitializedMemory)?;
        let vec: Vec<_> = memory.view()[ptr as usize..(ptr + len) as usize]
            .iter()
            .map(|cell| cell.get())
            .collect();
        Ok(vec)
    }

    pub fn write_bytes(&self, result_ptr: u64, bytes: Vec<u8>) -> Result<()> {
        let memory = self.inner.get_ref().ok_or(Error::UninitializedMemory)?;

        let offset = result_ptr as usize;
        memory.view()[offset..(offset + bytes.len())]
            .iter()
            .zip(bytes.iter())
            .for_each(|(cell, v)| cell.set(*v));
        Ok(())
    }
}

impl Default for AnomaMemory {
    fn default() -> Self {
        Self {
            inner: LazyInit::default(),
        }
    }
}
