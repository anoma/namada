//! Lazy hash map.

use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};

use super::super::Result;
use super::hasher::hash_for_storage_key;
use super::LazyCollection;
use crate::ledger::storage_api::{self, ResultExt, StorageRead, StorageWrite};
use crate::types::storage;

/// Subkey corresponding to the data elements of the LazyMap
pub const DATA_SUBKEY: &str = "data";

/// Lazy hash map.
///
/// This can be used as an alternative to `std::collections::HashMap` and
/// `BTreeMap`. In the lazy map, the elements do not reside in memory but are
/// instead read and written to storage sub-keys of the storage `key` given to
/// construct the map.
///
/// In the [`LazyHashMap`], the type of key `K` can be anything that
/// [`BorshSerialize`] and [`BorshDeserialize`] and a hex string of sha256 hash
/// over the borsh encoded keys are used as storage key segments.
///
/// This is different from [`super::LazyMap`], which uses [`storage::KeySeg`]
/// trait.
///
/// Additionally, [`LazyHashMap`] also writes the unhashed values into the
/// storage together with the values (using an internal `KeyVal` type).
pub struct LazyHashMap<K, V> {
    key: storage::Key,
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,
}

/// Struct to hold a key-value pair
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct KeyVal<K, V> {
    key: K,
    val: V,
}

impl<K, V> LazyCollection for LazyHashMap<K, V> {
    /// Create or use an existing map with the given storage `key`.
    fn new(key: storage::Key) -> Self {
        Self {
            key,
            phantom_k: PhantomData,
            phantom_v: PhantomData,
        }
    }
}

impl<K, V> LazyHashMap<K, V>
where
    K: BorshDeserialize + BorshSerialize + 'static,
    V: BorshDeserialize + BorshSerialize + 'static,
{
    /// Inserts a key-value pair into the map.
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
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let previous = self.get(storage, &key)?;

        let data_key = self.get_data_key(&key);
        Self::write_key_val(storage, &data_key, key, val)?;

        Ok(previous)
    }

    /// Removes a key from the map, returning the value at the key if the key
    /// was previously in the map.
    pub fn remove<S>(&self, storage: &mut S, key: &K) -> Result<Option<V>>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let value = self.get(storage, key)?;

        let data_key = self.get_data_key(key);
        storage.delete(&data_key)?;

        Ok(value)
    }

    /// Returns the value corresponding to the key, if any.
    pub fn get<S>(&self, storage: &S, key: &K) -> Result<Option<V>>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let res = self.get_key_val(storage, key)?;
        Ok(res.map(|(_key, val)| val))
    }

    /// Returns the key-value corresponding to the key, if any.
    pub fn get_key_val<S>(&self, storage: &S, key: &K) -> Result<Option<(K, V)>>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let data_key = self.get_data_key(key);
        Self::read_key_val(storage, &data_key)
    }

    /// Returns the key-value corresponding to the given hash of a key, if any.
    pub fn get_key_val_by_hash<S>(
        &self,
        storage: &S,
        key_hash: &str,
    ) -> Result<Option<(K, V)>>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let data_key =
            self.get_data_prefix().push(&key_hash.to_string()).unwrap();
        Self::read_key_val(storage, &data_key)
    }

    /// Returns whether the set contains a value.
    pub fn contains<S>(&self, storage: &S, key: &K) -> Result<bool>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        storage.has_key(&self.get_data_key(key))
    }

    /// Reads the number of elements in the map.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded maps to avoid gas usage increasing with the length of the
    /// set.
    #[allow(clippy::len_without_is_empty)]
    pub fn len<S>(&self, storage: &S) -> Result<u64>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let iter =
            storage_api::iter_prefix_bytes(storage, &self.get_data_prefix())?;
        iter.count().try_into().into_storage_result()
    }

    /// Returns whether the map contains no elements.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded maps to avoid gas usage increasing with the length of the
    /// set.
    pub fn is_empty<S>(&self, storage: &S) -> Result<bool>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let mut iter =
            storage_api::iter_prefix_bytes(storage, &self.get_data_prefix())?;
        Ok(iter.next().is_none())
    }

    /// An iterator visiting all key-value elements. The iterator element type
    /// is `Result<(K, V)>`, because iterator's call to `next` may fail with
    /// e.g. out of gas or data decoding error.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded maps to avoid gas usage increasing with the length of the
    /// map.
    pub fn iter<'iter>(
        &self,
        storage: &'iter impl StorageRead<'iter>,
    ) -> Result<impl Iterator<Item = Result<(K, V)>> + 'iter> {
        let iter = storage_api::iter_prefix(storage, &self.get_data_prefix())?;
        Ok(iter.map(|key_val_res| {
            let (_key, val) = key_val_res?;
            let KeyVal { key, val } = val;
            Ok((key, val))
        }))
    }

    /// Reads a key-value from storage
    fn read_key_val<S>(
        storage: &S,
        storage_key: &storage::Key,
    ) -> Result<Option<(K, V)>>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let res = storage.read(storage_key)?;
        Ok(res.map(|KeyVal { key, val }| (key, val)))
    }

    /// Write a key-value into storage
    fn write_key_val(
        storage: &mut impl StorageWrite,
        storage_key: &storage::Key,
        key: K,
        val: V,
    ) -> Result<()> {
        storage.write(storage_key, KeyVal { key, val })
    }

    /// Get the prefix of set's elements storage
    fn get_data_prefix(&self) -> storage::Key {
        self.key.push(&DATA_SUBKEY.to_owned()).unwrap()
    }

    /// Get the sub-key of a given element
    fn get_data_key(&self, key: &K) -> storage::Key {
        let hash_str = hash_for_storage_key(key);
        self.get_data_prefix().push(&hash_str).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ledger::storage::testing::TestStorage;

    #[test]
    fn test_lazy_hash_map_basics() -> storage_api::Result<()> {
        let mut storage = TestStorage::default();

        let key = storage::Key::parse("test").unwrap();
        let lazy_map = LazyHashMap::<u32, String>::new(key);

        // The map should be empty at first
        assert!(lazy_map.is_empty(&storage)?);
        assert!(lazy_map.len(&storage)? == 0);
        assert!(!lazy_map.contains(&storage, &0)?);
        assert!(!lazy_map.contains(&storage, &1)?);
        assert!(lazy_map.iter(&storage)?.next().is_none());
        assert!(lazy_map.get(&storage, &0)?.is_none());
        assert!(lazy_map.get(&storage, &1)?.is_none());
        assert!(lazy_map.remove(&mut storage, &0)?.is_none());
        assert!(lazy_map.remove(&mut storage, &1)?.is_none());

        // Insert a new value and check that it's added
        let (key, val) = (123, "Test".to_string());
        lazy_map.insert(&mut storage, key, val.clone())?;
        assert!(!lazy_map.contains(&storage, &0)?);
        assert!(lazy_map.contains(&storage, &key)?);
        assert!(!lazy_map.is_empty(&storage)?);
        assert!(lazy_map.len(&storage)? == 1);
        assert_eq!(
            lazy_map.iter(&storage)?.next().unwrap()?,
            (key, val.clone())
        );
        assert!(lazy_map.get(&storage, &0)?.is_none());
        assert_eq!(lazy_map.get(&storage, &key)?.unwrap(), val);

        // Remove the last value and check that the map is empty again
        let removed = lazy_map.remove(&mut storage, &key)?.unwrap();
        assert_eq!(removed, val);
        assert!(lazy_map.is_empty(&storage)?);
        assert!(lazy_map.len(&storage)? == 0);
        assert!(!lazy_map.contains(&storage, &0)?);
        assert!(!lazy_map.contains(&storage, &1)?);
        assert!(lazy_map.get(&storage, &0)?.is_none());
        assert!(lazy_map.get(&storage, &key)?.is_none());
        assert!(lazy_map.iter(&storage)?.next().is_none());
        assert!(lazy_map.remove(&mut storage, &key)?.is_none());

        Ok(())
    }
}
