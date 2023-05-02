//! Utilities to handle changed keys in storage.

use std::collections::BTreeSet;

use super::wl_storage::WlStorage;
use super::{DBIter, Key, StorageHasher, DB};
use crate::ledger::storage_api::{self, StorageWrite};

/// Wrapper around some [`StorageWrite`] implementation,
/// that keeps track of the keys modified on some scope.
pub struct ScopedChangedKeys<'db, S> {
    changed_keys: BTreeSet<Key>,
    storage: &'db mut S,
}

impl<'db, S> ScopedChangedKeys<'db, S> {
    /// Create a new intance of [`ScopedChangedKeys`].
    #[inline]
    pub fn new(storage: &'db mut S) -> Self {
        Self {
            storage,
            changed_keys: BTreeSet::new(),
        }
    }

    /// Return a reference to the inner storage implementation.
    #[inline]
    pub fn storage<'this: 'db>(&'this mut self) -> &'db mut S {
        self.storage
    }

    /// Return the modified storage keys.
    #[inline]
    pub fn into_changed_keys(self) -> BTreeSet<Key> {
        self.changed_keys
    }
}

impl<'db, D, H> StorageWrite for ScopedChangedKeys<'db, WlStorage<D, H>>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    #[inline]
    fn write_bytes(
        &mut self,
        key: &Key,
        val: impl AsRef<[u8]>,
    ) -> storage_api::Result<()> {
        self.changed_keys.insert(key.clone());
        self.storage.write_bytes(key, val)
    }

    #[inline]
    fn delete(&mut self, key: &Key) -> storage_api::Result<()> {
        self.changed_keys.insert(key.clone());
        self.storage.delete(key)
    }
}
