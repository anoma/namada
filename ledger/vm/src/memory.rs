use anoma_vm_env::memory;
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
    #[error("Exceeded memory bounds")]
    ExceededMemoryBounds,
}

pub type Result<T> = std::result::Result<T, Error>;

// The bounds are set in number of pages, the actual size is multiplied by
// `WASM_PAGE_SIZE = 64kiB`. The wasm code also occupies the memory space.
// TODO set bounds to accommodate for wasm env size
const TX_MIN_SIZE: u32 = 100; // 6.4 MiB
const TX_MAX_SIZE: u32 = 200; // 12.8 MiB
const VP_MIN_SIZE: u32 = 100; // 6.4 MiB
const VP_MAX_SIZE: u32 = 200; // 12.8 MiB

/// Prepare memory for instantiating a transaction module
pub fn prepare_tx_memory(store: &wasmer::Store) -> Result<wasmer::Memory> {
    let mem_type =
        wasmer::MemoryType::new(TX_MIN_SIZE, Some(TX_MAX_SIZE), false);
    Memory::new(store, mem_type).map_err(Error::InitMemoryError)
}

/// Prepare memory for instantiating a validity predicate module
pub fn prepare_vp_memory(store: &wasmer::Store) -> Result<wasmer::Memory> {
    let mem_type =
        wasmer::MemoryType::new(VP_MIN_SIZE, Some(VP_MAX_SIZE), false);
    let memory =
        Memory::new(store, mem_type).map_err(Error::InitMemoryError)?;
    log::info!("prepare VP memory size before: {}", memory.data_size());
    Ok(memory)
}

pub struct TxCallInput {
    pub tx_data_ptr: u64,
    pub tx_data_len: u64,
}

pub fn write_tx_inputs(
    memory: &wasmer::Memory,
    tx_data_bytes: &memory::TxData,
) -> Result<TxCallInput> {
    let tx_data_ptr = 0;
    let tx_data_len = tx_data_bytes.len() as _;

    write_memory_bytes(memory, tx_data_ptr, tx_data_bytes)
        .expect("TEMPORARY: failed to write input for transaction");

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
    memory: &wasmer::Memory,
    (addr, tx_data_bytes, write_log): memory::VpInput,
) -> Result<VpCallInput> {
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

    let bufs =
        [&addr_bytes[..], &tx_data_bytes[..], &write_log_bytes[..]].concat();
    write_memory_bytes(memory, addr_ptr, bufs)
        .expect("TEMPORARY: failed to write input for validity predicate");

    Ok(VpCallInput {
        addr_ptr,
        addr_len,
        tx_data_ptr,
        tx_data_len,
        write_log_ptr,
        write_log_len,
    })
}
/// Check that the given offset and length fits into the memory bounds
fn check_bounds(memory: &Memory, offset: u64, len: u64) -> Result<()> {
    if memory.data_size() < offset + len {
        Err(Error::ExceededMemoryBounds)
    } else {
        Ok(())
    }
}

/// Read bytes from memory at the given offset and length
fn read_memory_bytes(
    memory: &Memory,
    offset: u64,
    len: u64,
) -> Result<Vec<u8>> {
    check_bounds(memory, offset, len)?;
    let vec: Vec<_> = memory.view()[offset as usize..(offset + len) as usize]
        .iter()
        .map(|cell| cell.get())
        .collect();
    Ok(vec)
}

/// Write bytes into memory at the given offset
fn write_memory_bytes<T>(memory: &Memory, offset: u64, bytes: T) -> Result<()>
where
    T: AsRef<[u8]>,
{
    let slice = bytes.as_ref();
    let len = slice.len();
    check_bounds(memory, offset, len as _)?;
    let offset = offset as usize;
    memory.view()[offset..(offset + len)]
        .iter()
        .zip(slice.iter())
        .for_each(|(cell, v)| cell.set(*v));
    Ok(())
}

#[derive(Debug, Clone)]
pub struct AnomaMemory {
    inner: LazyInit<wasmer::Memory>,
}
impl AnomaMemory {
    /// Initialize the memory from the given exports, used to implement
    /// [`WasmerEnv`].
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

    /// Read bytes from memory at the given offset and length
    pub fn read_bytes(&self, offset: u64, len: u64) -> Result<Vec<u8>> {
        let memory = self.inner.get_ref().ok_or(Error::UninitializedMemory)?;
        read_memory_bytes(memory, offset, len)
    }

    /// Write bytes into memory at the given offset
    pub fn write_bytes<T>(&self, offset: u64, bytes: T) -> Result<()>
    where
        T: AsRef<[u8]>,
    {
        let memory = self.inner.get_ref().ok_or(Error::UninitializedMemory)?;
        write_memory_bytes(memory, offset, bytes)
    }

    /// Read string from memory at the given offset and bytes length
    pub fn read_string(&self, offset: u64, len: u64) -> Result<String> {
        let bytes = self.read_bytes(offset, len)?;
        Ok(std::str::from_utf8(&bytes)
            .expect("unable to decode string from memory")
            .to_string())
    }

    /// Write string into memory at the given offset
    pub fn write_string(&self, offset: u64, string: String) -> Result<()> {
        self.write_bytes(offset, string.as_bytes())
    }
}

impl Default for AnomaMemory {
    fn default() -> Self {
        Self {
            inner: LazyInit::default(),
        }
    }
}
