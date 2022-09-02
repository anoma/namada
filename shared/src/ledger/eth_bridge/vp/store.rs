//! Functionality for reading from storage in order to validate transactions

use borsh::BorshDeserialize;
use eyre::{Context, Result};

use crate::ledger::native_vp::Ctx;
use crate::ledger::storage as ledger_storage;
use crate::ledger::storage::StorageHasher;
use crate::types::storage::Key;
use crate::vm::WasmCacheAccess;

/// Read pre/post storage
pub(super) trait Reader {
    /// Storage read prior state (before tx execution). It will try to read from
    /// the storage.
    fn read_pre<T: BorshDeserialize>(&self, key: &Key) -> Result<Option<T>>;

    /// Storage read posterior state (after tx execution). It will try to read
    /// from the write log first and if no entry found then from the
    /// storage.
    fn read_post<T: BorshDeserialize>(&self, key: &Key) -> Result<Option<T>>;

    fn deserialize<T: BorshDeserialize>(
        x: Option<Vec<u8>>,
    ) -> Result<Option<T>> {
        let bytes = match x {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        let deserialized = T::try_from_slice(&bytes)
            .wrap_err_with(|| "couldn't deserialize".to_string())?;
        Ok(Some(deserialized))
    }
}

impl<'ctx, DB, H, CA> Reader for &Ctx<'ctx, DB, H, CA>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
    CA: 'static + WasmCacheAccess,
{
    fn read_pre<T: BorshDeserialize>(&self, key: &Key) -> Result<Option<T>> {
        let x = Ctx::read_pre(self, key)
            .wrap_err_with(|| format!("couldn't read_pre {}", key))?;
        Self::deserialize(x)
    }

    fn read_post<T: BorshDeserialize>(&self, key: &Key) -> Result<Option<T>> {
        let x = Ctx::read_post(self, key)
            .wrap_err_with(|| format!("couldn't read_post {}", key))?;
        Self::deserialize(x)
    }
}

#[cfg(any(test, feature = "testing"))]
pub(super) mod testing {
    use std::collections::HashMap;

    use super::*;

    #[derive(Debug, Default)]
    pub(in super::super) struct FakeReader {
        pre: HashMap<Key, Vec<u8>>,
        post: HashMap<Key, Vec<u8>>,
    }

    impl Reader for FakeReader {
        fn read_pre<T: BorshDeserialize>(
            &self,
            key: &Key,
        ) -> Result<Option<T>> {
            let bytes = match self.pre.get(key) {
                Some(bytes) => bytes.to_owned(),
                None => return Ok(None),
            };
            Self::deserialize(Some(bytes))
        }

        fn read_post<T: BorshDeserialize>(
            &self,
            key: &Key,
        ) -> Result<Option<T>> {
            let bytes = match self.post.get(key) {
                Some(bytes) => bytes.to_owned(),
                None => return Ok(None),
            };
            Self::deserialize(Some(bytes))
        }
    }
}
