use crate::types::TxMsg;
use anoma_vm_env::memory;
use borsh::BorshSerialize;
use std::io::Write;
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
    pub tx_data_ptr: i32,
    pub tx_data_len: i32,
}

pub fn write_tx_inputs(
    exports: &wasmer::Exports,
    tx_data: memory::TxDataIn,
) -> Result<TxCallInput> {
    let memory = exports
        .get_memory("memory")
        .map_err(Error::MemoryExportError)?;

    // TODO tx data is just bytes, the wrapper type is excessive, we could pass
    // them as is (also for VP)
    let mut tx_data_bytes = Vec::with_capacity(1024);
    tx_data
        .0
        .serialize(&mut tx_data_bytes)
        .expect("TEMPORARY: failed to serialize tx_data for transaction");
    let tx_data_ptr = 0;
    let tx_data_len = tx_data_bytes.len() as i32;

    // TODO check size and grow memory if needed
    let mut data = unsafe { memory.data_unchecked_mut() };
    let bufs = tx_data_bytes;
    data.write(&bufs)
        .expect("TEMPORARY: failed to write tx_data for transaction");

    Ok(TxCallInput {
        tx_data_ptr,
        tx_data_len,
    })
}

pub struct VpCallInput {
    pub tx_data_ptr: i32,
    pub tx_data_len: i32,
    pub write_log_ptr: i32,
    pub write_log_len: i32,
}

pub fn write_vp_inputs(
    exports: &wasmer::Exports,
    (tx_data, write_log): memory::VpIn,
) -> Result<VpCallInput> {
    let memory = exports
        .get_memory("memory")
        .map_err(Error::MemoryExportError)?;

    let mut tx_data_bytes = Vec::with_capacity(1024);
    tx_data.0.serialize(&mut tx_data_bytes).expect(
        "TEMPORARY: failed to serialize tx_data for validity predicate",
    );
    let tx_data_ptr = 0;
    let tx_data_len = tx_data_bytes.len() as i32;

    let mut write_log_bytes = Vec::with_capacity(1024);
    write_log.serialize(&mut write_log_bytes).expect(
        "TEMPORARY: failed to serialize write_log for validity predicate",
    );
    let write_log_ptr = tx_data_ptr + tx_data_len;
    let write_log_len = write_log_bytes.len() as i32;

    // TODO check size and grow memory if needed
    let mut data = unsafe { memory.data_unchecked_mut() };
    let bufs = [tx_data_bytes, write_log_bytes].concat();
    data.write(&bufs)
        .expect("TEMPORARY: failed to write tx_data for validity predicate");

    Ok(VpCallInput {
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

    /// Read a [`Tx_msg`] from memory
    pub fn read_tx(
        &self,
        src_ptr: i32,
        src_len: i32,
        dest_ptr: i32,
        dest_len: i32,
        amount: u64,
    ) -> Result<TxMsg> {
        let memory = self.inner.get_ref().ok_or(Error::UninitializedMemory)?;
        let src_vec: Vec<_> = memory.view()
            [src_ptr as usize..(src_ptr + src_len) as usize]
            .iter()
            .map(|cell| cell.get())
            .collect();
        let src = std::str::from_utf8(&src_vec).unwrap().to_string();

        let dest_vec: Vec<_> = memory.view()
            [dest_ptr as usize..(dest_ptr + dest_len) as usize]
            .iter()
            .map(|cell| cell.get())
            .collect();
        let dest = std::str::from_utf8(&dest_vec).unwrap().to_string();

        log::debug!(
            "transfer called with src: {}, dest: {}, amount: {}",
            src,
            dest,
            amount
        );

        Ok(TxMsg { src, dest, amount })
    }
}

impl Default for AnomaMemory {
    fn default() -> Self {
        Self {
            inner: LazyInit::default(),
        }
    }
}
