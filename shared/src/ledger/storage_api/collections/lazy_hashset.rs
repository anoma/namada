//! Lazy hash set.

use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};

use super::super::Result;
use super::hasher::hash_for_storage_key;
use crate::ledger::storage_api::{self, StorageRead, StorageWrite};
use crate::types::storage;

/// Subkey corresponding to the data elements of the LazySet
pub const DATA_SUBKEY: &str = "data";

/// Lazy hash set.
///
/// This can be used as an alternative to `std::collections::HashSet` and
/// `BTreeSet`. In the lazy set, the elements do not reside in memory but are
/// instead read and written to storage sub-keys of the storage `key` given to
/// construct the set.
///
/// In the [`LazyHashSet`], the type of value `T` can be anything that
/// [`BorshSerialize`] and [`BorshDeserialize`] and a hex string of sha256 hash
/// over the borsh encoded values are used as storage key segments.
///
/// This is different from [`super::LazySet`], which uses [`storage::KeySeg`]
/// trait.
///
/// Additionally, [`LazyHashSet`] also writes the unhashed values into the
/// storage.
pub struct LazyHashSet<T> {
    key: storage::Key,
    phantom: PhantomData<T>,
}

impl<T> LazyHashSet<T>
where
    T: BorshSerialize + BorshDeserialize + 'static,
{
    /// Create or use an existing set with the given storage `key`.
    pub fn new(key: storage::Key) -> Self {
        Self {
            key,
            phantom: PhantomData,
        }
    }

    /// Adds a value to the set. If the set did not have this value present,
    /// `Ok(true)` is returned, `Ok(false)` otherwise.
    pub fn insert<S>(&self, storage: &mut S, val: &T) -> Result<bool>
    where
        S: StorageWrite + StorageRead,
    {
        if self.contains(storage, val)? {
            Ok(false)
        } else {
            let data_key = self.get_data_key(val);
            storage.write(&data_key, &val)?;
            Ok(true)
        }
    }

    /// Removes a value from the set. Returns whether the value was present in
    /// the set.
    pub fn remove<S>(&self, storage: &mut S, val: &T) -> Result<bool>
    where
        S: StorageWrite + StorageRead,
    {
        let data_key = self.get_data_key(val);
        let value: Option<T> = storage.read(&data_key)?;
        storage.delete(&data_key)?;
        Ok(value.is_some())
    }

    /// Returns whether the set contains a value.
    pub fn contains(
        &self,
        storage: &impl StorageRead,
        val: &T,
    ) -> Result<bool> {
        let value: Option<T> = storage.read(&self.get_data_key(val))?;
        Ok(value.is_some())
    }

    /// Returns whether the set contains no elements.
    pub fn is_empty(&self, storage: &impl StorageRead) -> Result<bool> {
        let mut iter = storage.iter_prefix(&self.get_data_prefix())?;
        Ok(storage.iter_next(&mut iter)?.is_none())
    }

    /// An iterator visiting all elements. The iterator element type is
    /// `Result<T>`, because iterator's call to `next` may fail with e.g. out of
    /// gas or data decoding error.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded sets to avoid gas usage increasing with the length of the
    /// set.
    pub fn iter<'a>(
        &self,
        storage: &'a impl StorageRead,
    ) -> Result<impl Iterator<Item = Result<T>> + 'a> {
        let iter = storage_api::iter_prefix(storage, &self.get_data_prefix())?;
        Ok(iter.map(|key_val_res| {
            let (_key, val) = key_val_res?;
            Ok(val)
        }))
    }

    /// Get the prefix of set's elements storage
    fn get_data_prefix(&self) -> storage::Key {
        self.key.push(&DATA_SUBKEY.to_owned()).unwrap()
    }

    /// Get the sub-key of a given element
    fn get_data_key(&self, val: &T) -> storage::Key {
        let hash_str = hash_for_storage_key(val);
        self.get_data_prefix().push(&hash_str).unwrap()
    }
}
