/// WASM Cache access level, used to limit dry-ran transactions to read-only
/// cache access.
pub trait WasmCacheAccess: Clone + std::fmt::Debug + Default {
    /// Is access read/write?
    fn is_read_write() -> bool;
}

/// Regular read/write caches access
#[derive(Debug, Clone, Default)]
pub struct WasmCacheRwAccess;
impl WasmCacheAccess for WasmCacheRwAccess {
    fn is_read_write() -> bool {
        true
    }
}

/// Restricted read-only access for dry-ran transactions
#[derive(Debug, Clone, Default)]
pub struct WasmCacheRoAccess;

impl WasmCacheAccess for WasmCacheRoAccess {
    fn is_read_write() -> bool {
        false
    }
}
