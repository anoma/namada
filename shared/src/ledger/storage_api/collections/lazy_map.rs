//! Lazy map.

use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};

use super::super::Result;
use super::ReadError;
use crate::ledger::storage_api::{self, ResultExt, StorageRead, StorageWrite};
use crate::types::storage::{self, KeySeg};

/// Subkey corresponding to the data elements of the LazyMap
pub const DATA_SUBKEY: &str = "data";

/// Lazy map.
///
/// This can be used as an alternative to `std::collections::HashMap` and
/// `BTreeMap`. In the lazy map, the elements do not reside in memory but are
/// instead read and written to storage sub-keys of the storage `key` used to
/// construct the map.
///
/// In the [`LazyMap`], the type of key `K` can be anything that implements
/// [`storage::KeySeg`] and this trait is used to turn the keys into key
/// segments.
///
/// This is different from [`super::LazyHashMap`], which hashes borsh encoded
/// key.
pub struct LazyMap<K, V> {
    key: storage::Key,
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,
}

impl<K, V> LazyMap<K, V>
where
    K: storage::KeySeg,
    V: BorshDeserialize + BorshSerialize + 'static,
{
    /// Create or use an existing map with the given storage `key`.
    pub fn new(key: storage::Key) -> Self {
        Self {
            key,
            phantom_k: PhantomData,
            phantom_v: PhantomData,
        }
    }

    /// Inserts a key-value pair into the map.
    ///
    /// The full storage key identifies the key in the pair, while the value is
    /// held within the storage key.
    ///
    /// If the map did not have this key present, `None` is returned.
    /// If the map did have this key present, the value is updated, and the old
    /// value is returned. Unlike in `std::collection::HashMap`, the key is also
    /// updated; this matters for types that can be `==` without being
    /// identical.
    pub fn insert<S>(
        &self,
        storage: &mut S,
        key: K,
        val: V,
    ) -> Result<Option<V>>
    where
        S: StorageWrite + StorageRead,
    {
        let previous = self.get(storage, &key)?;

        let data_key = self.get_data_key(&key);
        Self::write_key_val(storage, &data_key, val)?;

        Ok(previous)
    }

    /// Removes a key from the map, returning the value at the key if the key
    /// was previously in the map.
    pub fn remove<S>(&self, storage: &mut S, key: &K) -> Result<Option<V>>
    where
        S: StorageWrite + StorageRead,
    {
        let value = self.get(storage, key)?;

        let data_key = self.get_data_key(key);
        storage.delete(&data_key)?;

        Ok(value)
    }

    /// Returns the value corresponding to the key, if any.
    pub fn get(
        &self,
        storage: &impl StorageRead,
        key: &K,
    ) -> Result<Option<V>> {
        let data_key = self.get_data_key(key);
        Self::read_key_val(storage, &data_key)
    }

    /// An iterator visiting all key-value elements. The iterator element type
    /// is `Result<(K, V)>`, because iterator's call to `next` may fail with
    /// e.g. out of gas or data decoding error.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded sets to avoid gas usage increasing with the length of the
    /// map.
    pub fn iter<'a>(
        &self,
        storage: &'a impl StorageRead,
    ) -> Result<impl Iterator<Item = Result<(K, V)>> + 'a> {
        let iter = storage_api::iter_prefix(storage, &self.get_data_prefix())?;
        Ok(iter.map(|key_val_res| {
            let (key, val) = key_val_res?;
            let last_key_seg = key
                .last()
                .ok_or(ReadError::UnexpectedlyEmptyStorageKey)
                .into_storage_result()?;
            let key = K::parse(last_key_seg.raw()).into_storage_result()?;
            Ok((key, val))
        }))
    }

    /// Reads a value from storage
    fn read_key_val(
        storage: &impl StorageRead,
        storage_key: &storage::Key,
    ) -> Result<Option<V>> {
        let res = storage.read(storage_key)?;
        Ok(res)
    }

    /// Write a value into storage
    fn write_key_val(
        storage: &mut impl StorageWrite,
        storage_key: &storage::Key,
        val: V,
    ) -> Result<()> {
        storage.write(storage_key, val)
    }

    /// Get the prefix of set's elements storage
    fn get_data_prefix(&self) -> storage::Key {
        self.key.push(&DATA_SUBKEY.to_owned()).unwrap()
    }

    /// Get the sub-key of a given element
    fn get_data_key(&self, key: &K) -> storage::Key {
        let key_str = key.to_db_key();
        self.get_data_prefix().push(&key_str).unwrap()
    }
}
