use anoma_vm_env::memory;
use borsh::BorshSerialize;
use thiserror::Error;
use wasmer::{HostEnvInitError, LazyInit, Memory};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed initializing the memory: {0}")]
    InitMemoryError(wasmer::MemoryError),
    #[error("Memory is not initialized")]
    UninitializedMemory,
    #[error("Memory ouf of bounds: {0}")]
    MemoryOutOfBounds(wasmer::MemoryError),
}

pub type Result<T> = std::result::Result<T, Error>;

// The bounds are set in number of pages, the actual size is multiplied by
// `wasmer::WASM_PAGE_SIZE = 64kiB`. The wasm code also occupies the memory
// space.
// TODO set bounds to accommodate for wasm env size
const TX_MEMORY_INIT_PAGES: u32 = 100; // 6.4 MiB
const TX_MEMORY_MAX_PAGES: u32 = 200; // 12.8 MiB
const VP_MEMORY_INIT_PAGES: u32 = 100; // 6.4 MiB
const VP_MEMORY_MAX_PAGES: u32 = 200; // 12.8 MiB
const MATCHMAKER_MEMORY_INIT_PAGES: u32 = 400; // 12.8 MiB
const FILTER_MEMORY_INIT_PAGES: u32 = 100; // 6.4 MiB
const FILTER_MEMORY_MAX_PAGES: u32 = 200; // 12.8 MiB

/// Prepare memory for instantiating a transaction module
pub fn prepare_tx_memory(store: &wasmer::Store) -> Result<wasmer::Memory> {
    let mem_type = wasmer::MemoryType::new(
        TX_MEMORY_INIT_PAGES,
        Some(TX_MEMORY_MAX_PAGES),
        false,
    );
    Memory::new(store, mem_type).map_err(Error::InitMemoryError)
}

/// Prepare memory for instantiating a validity predicate module
pub fn prepare_vp_memory(store: &wasmer::Store) -> Result<wasmer::Memory> {
    let mem_type = wasmer::MemoryType::new(
        VP_MEMORY_INIT_PAGES,
        Some(VP_MEMORY_MAX_PAGES),
        false,
    );
    let memory =
        Memory::new(store, mem_type).map_err(Error::InitMemoryError)?;
    Ok(memory)
}

/// Prepare memory for instantiating a matchmaker module
pub fn prepare_matchmaker_memory(
    store: &wasmer::Store,
) -> Result<wasmer::Memory> {
    let mem_type =
        wasmer::MemoryType::new(MATCHMAKER_MEMORY_INIT_PAGES, None, false);
    Memory::new(store, mem_type).map_err(Error::InitMemoryError)
}

/// Prepare memory for instantiating a filter module
pub fn prepare_filter_memory(store: &wasmer::Store) -> Result<wasmer::Memory> {
    let mem_type = wasmer::MemoryType::new(
        FILTER_MEMORY_INIT_PAGES,
        Some(FILTER_MEMORY_MAX_PAGES),
        false,
    );
    Memory::new(store, mem_type).map_err(Error::InitMemoryError)
}

pub struct TxCallInput {
    pub tx_data_ptr: u64,
    pub tx_data_len: u64,
}

/// Write transaction inputs into wasm memory
pub fn write_tx_inputs(
    memory: &wasmer::Memory,
    tx_data_bytes: &memory::Data,
) -> Result<TxCallInput> {
    let tx_data_ptr = 0;
    let tx_data_len = tx_data_bytes.len() as _;

    write_memory_bytes(memory, tx_data_ptr, tx_data_bytes)?;

    Ok(TxCallInput {
        tx_data_ptr,
        tx_data_len,
    })
}

#[derive(Clone, Debug)]
pub struct VpCallInput {
    pub addr_ptr: u64,
    pub addr_len: u64,
    pub tx_data_ptr: u64,
    pub tx_data_len: u64,
    pub keys_changed_ptr: u64,
    pub keys_changed_len: u64,
    pub verifiers_ptr: u64,
    pub verifiers_len: u64,
}

/// Write validity predicate inputs into wasm memory
pub fn write_vp_inputs(
    memory: &wasmer::Memory,
    (addr, tx_data_bytes, keys_changed, verifiers): memory::VpInput,
) -> Result<VpCallInput> {
    let addr_ptr = 0;
    // String utf8 encoding is more space-efficient than Borsh encoding
    let addr_bytes = addr.as_bytes();
    let addr_len = addr_bytes.len() as _;

    let tx_data_ptr = addr_ptr + addr_len;
    let tx_data_len = tx_data_bytes.len() as _;

    let keys_changed_bytes = keys_changed.try_to_vec().expect(
        "TEMPORARY: failed to serialize keys_changed for validity predicate",
    );
    let keys_changed_ptr = tx_data_ptr + tx_data_len;
    let keys_changed_len = keys_changed_bytes.len() as _;

    let verifiers_bytes = verifiers.try_to_vec().expect(
        "TEMPORARY: failed to serialize verifiers for validity predicate",
    );
    let verifiers_ptr = keys_changed_ptr + keys_changed_len;
    let verifiers_len = verifiers_bytes.len() as _;

    let bytes = [
        &addr_bytes[..],
        tx_data_bytes,
        &keys_changed_bytes[..],
        &verifiers_bytes[..],
    ]
    .concat();
    write_memory_bytes(memory, addr_ptr, bytes)?;

    Ok(VpCallInput {
        addr_ptr,
        addr_len,
        tx_data_ptr,
        tx_data_len,
        keys_changed_ptr,
        keys_changed_len,
        verifiers_ptr,
        verifiers_len,
    })
}

pub struct MatchmakerCallInput {
    pub intent_data_1_ptr: u64,
    pub intent_data_1_len: u64,
    pub intent_data_2_ptr: u64,
    pub intent_data_2_len: u64,
}

pub fn write_matchmaker_inputs(
    memory: &wasmer::Memory,
    intent_data_1: impl AsRef<[u8]>,
    intent_data_2: impl AsRef<[u8]>,
) -> Result<MatchmakerCallInput> {
    let intent_data_1_ptr = 0;
    let intent_data_1_len = intent_data_1.as_ref().len() as _;

    let intent_data_2_ptr = intent_data_1_ptr + intent_data_1_len;
    let intent_data_2_len = intent_data_2.as_ref().len() as _;

    log::info!("write_data_inputs {}", intent_data_1_len);
    write_memory_bytes(memory, intent_data_1_ptr, intent_data_1)?;
    log::info!("write_data_inputs {}", intent_data_2_len);
    write_memory_bytes(memory, intent_data_2_ptr, intent_data_2)?;

    Ok(MatchmakerCallInput {
        intent_data_1_ptr,
        intent_data_1_len,
        intent_data_2_ptr,
        intent_data_2_len,
    })
}

pub struct FilterCallInput {
    pub intent_data_ptr: u64,
    pub intent_data_len: u64,
}

pub fn write_filter_inputs(
    memory: &wasmer::Memory,
    intent_data: impl AsRef<[u8]>,
) -> Result<FilterCallInput> {
    let intent_data_ptr = 0;
    let intent_data_len = intent_data.as_ref().len() as _;

    log::info!("write_data_inputs of len {}", intent_data_len);
    write_memory_bytes(memory, intent_data_ptr, intent_data)?;

    Ok(FilterCallInput {
        intent_data_ptr,
        intent_data_len,
    })
}

/// Check that the given offset and length fits into the memory bounds. If not,
/// it will try to grow the memory.
fn check_bounds(memory: &Memory, offset: u64, len: usize) -> Result<()> {
    log::debug!(
        "check_bounds pages {}, data_size {}, offset + len {}",
        memory.size().0,
        memory.data_size(),
        offset + len as u64
    );
    if memory.data_size() < offset + len as u64 {
        let cur_pages = memory.size().0;
        let capacity = cur_pages as usize * wasmer::WASM_PAGE_SIZE;
        let missing = offset as usize + len - capacity;
        // Ceiling division
        let req_pages = ((missing + wasmer::WASM_PAGE_SIZE - 1)
            / wasmer::WASM_PAGE_SIZE) as u32;
        log::info!("trying to grow memory by {} pages", req_pages);
        memory
            .grow(req_pages)
            .map(|_pages| ())
            .map_err(Error::MemoryOutOfBounds)
    } else {
        Ok(())
    }
}

/// Read bytes from memory at the given offset and length
fn read_memory_bytes(
    memory: &Memory,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>> {
    check_bounds(memory, offset, len)?;
    let offset = offset as usize;
    let vec: Vec<_> = memory.view()[offset..(offset + len)]
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
    /// [`wasmer::WasmerEnv`].
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
    pub fn read_bytes(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
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
    pub fn read_string(&self, offset: u64, len: usize) -> Result<String> {
        let bytes = self.read_bytes(offset, len)?;
        Ok(std::str::from_utf8(&bytes)
            .expect("unable to decode string from memory")
            .to_string())
    }

    /// Write string into memory at the given offset
    #[allow(dead_code)]
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
