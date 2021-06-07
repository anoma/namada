//! Wasm memory is used for bi-directionally passing data between the host and a
//! wasm instance.

use borsh::BorshSerialize;
use thiserror::Error;
use wasmer::{HostEnvInitError, LazyInit, Memory};

use crate::vm::memory::VmMemory;
use crate::vm::types::VpInput;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed initializing the memory: {0}")]
    InitMemoryError(wasmer::MemoryError),
    #[error("Memory ouf of bounds: {0}")]
    MemoryOutOfBounds(wasmer::MemoryError),
}

/// Result of a function that may fail
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
    let mem_type =
        wasmer::MemoryType::new(FILTER_MEMORY_INIT_PAGES, None, false);
    Memory::new(store, mem_type).map_err(Error::InitMemoryError)
}

/// Input data for transaction wasm call
pub struct TxCallInput {
    /// Raw pointer to the data
    pub tx_data_ptr: u64,
    /// Length of the data
    pub tx_data_len: u64,
}

/// Write transaction inputs into wasm memory
pub fn write_tx_inputs(
    memory: &wasmer::Memory,
    tx_data_bytes: Vec<u8>,
) -> Result<TxCallInput> {
    let tx_data_ptr = 0;
    let tx_data_len = tx_data_bytes.len() as _;

    write_memory_bytes(memory, tx_data_ptr, tx_data_bytes)?;

    Ok(TxCallInput {
        tx_data_ptr,
        tx_data_len,
    })
}

/// Input data for validity predicate wasm call
#[derive(Clone, Debug)]
pub struct VpCallInput {
    /// Pointer to the address
    pub addr_ptr: u64,
    /// Length of the address
    pub addr_len: u64,
    /// Pointer to the data
    pub data_ptr: u64,
    /// Length of the data
    pub data_len: u64,
    /// Pointer to the serialized changed keys
    pub keys_changed_ptr: u64,
    /// Length of the serialized changed keys
    pub keys_changed_len: u64,
    /// Pointer to the serialized verifiers
    pub verifiers_ptr: u64,
    /// Length of the serialized verifiers
    pub verifiers_len: u64,
}

/// Write validity predicate inputs into wasm memory
pub fn write_vp_inputs(
    memory: &wasmer::Memory,
    VpInput {
        addr,
        data,
        keys_changed,
        verifiers,
    }: VpInput,
) -> Result<VpCallInput> {
    let addr_ptr = 0;
    let addr_bytes = addr.try_to_vec().expect(
        "TEMPORARY: failed to serialize address for validity predicate",
    );
    let addr_len = addr_bytes.len() as _;

    let data_ptr = addr_ptr + addr_len;
    let data_len = data.len() as _;

    let keys_changed_bytes = keys_changed.try_to_vec().expect(
        "TEMPORARY: failed to serialize keys_changed for validity predicate",
    );
    let keys_changed_ptr = data_ptr + data_len;
    let keys_changed_len = keys_changed_bytes.len() as _;

    let verifiers_bytes = verifiers.try_to_vec().expect(
        "TEMPORARY: failed to serialize verifiers for validity predicate",
    );
    let verifiers_ptr = keys_changed_ptr + keys_changed_len;
    let verifiers_len = verifiers_bytes.len() as _;

    let bytes = [
        &addr_bytes[..],
        data,
        &keys_changed_bytes[..],
        &verifiers_bytes[..],
    ]
    .concat();
    write_memory_bytes(memory, addr_ptr, bytes)?;

    Ok(VpCallInput {
        addr_ptr,
        addr_len,
        data_ptr,
        data_len,
        keys_changed_ptr,
        keys_changed_len,
        verifiers_ptr,
        verifiers_len,
    })
}

/// Input data for matchmaker wasm call
pub struct MatchmakerCallInput {
    /// Pointer to the data
    pub data_ptr: u64,
    /// Length of the data
    pub data_len: u64,
    /// Pointer to the intent ID
    pub intent_id_ptr: u64,
    /// Length of the intent ID
    pub intent_id_len: u64,
    /// Pointer to the intent data
    pub intent_data_ptr: u64,
    /// Length of the intent data
    pub intent_data_len: u64,
}

/// Write matchmaker inputs into wasm memory
pub fn write_matchmaker_inputs(
    memory: &wasmer::Memory,
    data: impl AsRef<[u8]>,
    intent_id: impl AsRef<[u8]>,
    intent_data: impl AsRef<[u8]>,
) -> Result<MatchmakerCallInput> {
    let data_ptr = 0;
    let data_len = data.as_ref().len() as _;

    let intent_id_ptr = data_ptr + data_len;
    let intent_id_len = intent_id.as_ref().len() as _;

    let intent_data_ptr = intent_id_ptr + intent_id_len;
    let intent_data_len = intent_data.as_ref().len() as _;

    write_memory_bytes(memory, data_ptr, data)?;
    write_memory_bytes(memory, intent_id_ptr, intent_id)?;
    write_memory_bytes(memory, intent_data_ptr, intent_data)?;

    Ok(MatchmakerCallInput {
        data_ptr,
        data_len,
        intent_id_ptr,
        intent_id_len,
        intent_data_ptr,
        intent_data_len,
    })
}

/// Input data for matchmaker filter wasm call
pub struct FilterCallInput {
    /// Pointer to the intent data
    pub intent_data_ptr: u64,
    /// Length of the intent data
    pub intent_data_len: u64,
}

/// Write matchmaker filter inputs into wasm memory
pub fn write_filter_inputs(
    memory: &wasmer::Memory,
    intent_data: impl AsRef<[u8]>,
) -> Result<FilterCallInput> {
    let intent_data_ptr = 0;
    let intent_data_len = intent_data.as_ref().len() as _;

    tracing::info!("write_data_inputs of len {}", intent_data_len);
    write_memory_bytes(memory, intent_data_ptr, intent_data)?;

    Ok(FilterCallInput {
        intent_data_ptr,
        intent_data_len,
    })
}

/// Check that the given offset and length fits into the memory bounds. If not,
/// it will try to grow the memory.
fn check_bounds(memory: &Memory, offset: u64, len: usize) -> Result<()> {
    tracing::debug!(
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
        tracing::info!("trying to grow memory by {} pages", req_pages);
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

/// The wasm memory
#[derive(Debug, Clone)]
pub struct WasmMemory {
    inner: LazyInit<wasmer::Memory>,
}

impl WasmMemory {
    /// Initialize the memory from the given exports, used to implement
    /// [`wasmer::WasmerEnv`].
    pub fn init_env_memory(
        &mut self,
        exports: &wasmer::Exports,
    ) -> std::result::Result<(), HostEnvInitError> {
        let memory = exports.get_memory("memory")?;
        if !self.inner.initialize(memory.clone()) {
            tracing::error!("wasm memory is already initialized");
        }
        Ok(())
    }
}

impl VmMemory for WasmMemory {
    /// Read bytes from memory at the given offset and length, return the bytes
    /// and the gas cost
    fn read_bytes(&self, offset: u64, len: usize) -> (Vec<u8>, u64) {
        let memory =
            self.inner.get_ref().expect("Memory should be initialized");
        let bytes = read_memory_bytes(memory, offset, len)
            .expect("Reading memory shouldn't fail");
        let gas = bytes.len();
        (bytes, gas as _)
    }

    /// Write bytes into memory at the given offset and return the gas cost
    fn write_bytes<T>(&self, offset: u64, bytes: T) -> u64
    where
        T: AsRef<[u8]>,
    {
        let gas = bytes.as_ref().len();
        let memory =
            self.inner.get_ref().expect("Memory should be initialized");
        write_memory_bytes(memory, offset, bytes)
            .expect("Writing memory shouldn't fail");
        gas as _
    }

    /// Read string from memory at the given offset and bytes length, and return
    /// the gas cost
    fn read_string(&self, offset: u64, len: usize) -> (String, u64) {
        let (bytes, gas) = self.read_bytes(offset, len);
        let string = std::str::from_utf8(&bytes)
            .expect("Decoding string from memory shouldn't fail")
            .to_string();
        (string, gas as _)
    }

    /// Write string into memory at the given offset and return the gas cost
    #[allow(dead_code)]
    fn write_string(&self, offset: u64, string: String) -> u64 {
        self.write_bytes(offset, string.as_bytes())
    }
}

impl Default for WasmMemory {
    fn default() -> Self {
        Self {
            inner: LazyInit::default(),
        }
    }
}
