use std::io::Write;

use crate::types::TxMsg;
use borsh::BorshSerialize;
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

#[derive(Debug, Clone)]
pub struct AnomaMemory {
    inner: LazyInit<wasmer::Memory>,
}

impl AnomaMemory {
    /// Prepare memory for running a transaction
    pub fn prepare_tx_memory(store: &wasmer::Store) -> Result<wasmer::Memory> {
        let mem_type = wasmer::MemoryType::new(1, None, false);
        Memory::new(store, mem_type)
            .map_err(|e| Error::InitMemoryError(e).into())
    }

    /// Prepare memory for running a validity predicate
    pub fn prepare_vp_memory(store: &wasmer::Store) -> Result<wasmer::Memory> {
        let mem_type = wasmer::MemoryType::new(1, None, false);
        Memory::new(store, mem_type)
            .map_err(|e| Error::InitMemoryError(e).into())
    }

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

    /// Write a [`Tx_msg`] into memory and return a pointer and the data length
    pub fn write_tx_msg(
        exports: &wasmer::Exports,
        tx_msg: &TxMsg,
    ) -> Result<(i32, i32)> {
        let memory = exports
            .get_memory("memory")
            .map_err(|e| Error::MemoryExportError(e).into())?;
        let mut tx_bytes = Vec::with_capacity(1024);
        tx_msg.serialize(&mut tx_bytes).expect("TEMPORARY: failed to serialize TxMsg for validity predicate - this will be handled in memory module");
        // TODO: do this safely in a customized memory implementation
        let mut data = unsafe { memory.data_unchecked_mut() };
        // NOTE: the memory is initialized with 1 page (64kb in
        // `wasmer::Pages`), so this data fits in
        data.write(&tx_bytes).expect("TEMPORARY: failed to write TxMsg for validity predicate - this will be handled in memory module");
        Ok((0, tx_bytes.len() as i32))
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
