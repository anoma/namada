//! Functionality for reading from storage in order to validate transactions

use eyre::{Context, Result};

use crate::ledger::native_vp::Ctx;
use crate::ledger::storage as ledger_storage;
use crate::ledger::storage::StorageHasher;
use crate::types::storage::Key;
use crate::vm::WasmCacheAccess;

pub(super) trait StorageReader {
    /// Storage read prior state (before tx execution). It will try to read from
    /// the storage.
    fn read_pre(&self, key: &Key) -> Result<Option<Vec<u8>>>;

    /// Storage read posterior state (after tx execution). It will try to read
    /// from the write log first and if no entry found then from the
    /// storage.
    fn read_post(&self, key: &Key) -> Result<Option<Vec<u8>>>;
}

impl<'ctx, DB, H, CA> StorageReader for &Ctx<'ctx, DB, H, CA>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
    CA: 'static + WasmCacheAccess,
{
    fn read_pre(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        Ctx::read_pre(&self, key)
            .wrap_err_with(|| format!("couldn't read_pre {}", key))
    }

    fn read_post(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        Ctx::read_post(&self, key)
            .wrap_err_with(|| format!("couldn't read_post {}", key))
    }
}
