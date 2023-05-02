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

#[cfg(test)]
mod test_changed_keys {
    use super::*;
    use crate::ledger::storage::testing::TestWlStorage;
    use crate::types::storage::DbKeySeg;

    #[test]
    fn test_get_changed_keys() {
        let key_1 = DbKeySeg::StringSeg("one".into()).into();
        let key_2 = DbKeySeg::StringSeg("two".into()).into();
        let key_3 = DbKeySeg::StringSeg("three".into()).into();

        let mut wl_storage = TestWlStorage::default();

        wl_storage.write(&key_1, 1u32).expect("Test failed");

        let mut scoped_storage = ScopedChangedKeys::new(&mut wl_storage);

        scoped_storage.write(&key_2, 2u32).expect("Test failed");
        scoped_storage.write(&key_3, 3u32).expect("Test failed");

        let changed_keys = scoped_storage.into_changed_keys();
        let expected_keys = BTreeSet::from([key_2, key_3]);

        assert_eq!(changed_keys, expected_keys);
    }
}
