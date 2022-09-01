//! Lazy map.

use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};

use super::super::Result;
use super::{LazyCollection, ReadError};
use crate::ledger::storage_api::validation::Data;
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
#[derive(Debug)]
pub struct LazyMap<K, V> {
    key: storage::Key,
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,
}

/// Possible sub-keys of a [`LazyMap`]
#[derive(Debug)]
pub enum SubKey<K> {
    /// Data sub-key, further sub-keyed by its literal map key
    Data(K),
}

/// Possible sub-keys of a [`LazyMap`], together with their [`validation::Data`]
/// that contains prior and posterior state.
#[derive(Debug)]
pub enum SubKeyWithData<K, V> {
    /// Data sub-key, further sub-keyed by its literal map key
    Data(K, Data<V>),
}

/// Possible actions that can modify a [`LazyMap`]. This roughly corresponds to
/// the methods that have `StorageWrite` access.
/// TODO: In a nested collection, `V` may be an action inside the nested
/// collection.
#[derive(Debug)]
pub enum Action<K, V> {
    /// Insert or update a value `V` at key `K` in a [`LazyMap<K, V>`].
    Insert(K, V),
    /// Remove a value `V` at key `K` from a [`LazyMap<K, V>`].
    Remove(K, V),
}

/// TODO: In a nested collection, `V` may be an action inside the nested
/// collection.
#[derive(Debug)]
pub enum Nested<K, V> {
    /// Insert or update a value `V` at key `K` in a [`LazyMap<K, V>`].
    Insert(K, V),
    /// Remove a value `V` at key `K` from a [`LazyMap<K, V>`].
    Remove(K, V),
}

impl<K, V> LazyCollection for LazyMap<K, V>
where
    K: storage::KeySeg,
{
    /// Create or use an existing map with the given storage `key`.
    fn new(key: storage::Key) -> Self {
        Self {
            key,
            phantom_k: PhantomData,
            phantom_v: PhantomData,
        }
    }
}

// Generic `LazyMap` methods that require no bounds on values `V`
impl<K, V> LazyMap<K, V>
where
    K: storage::KeySeg,
{
    /// Returns whether the set contains a value.
    pub fn contains<S>(&self, storage: &S, key: &K) -> Result<bool>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        storage.has_key(&self.get_data_key(key))
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

// `LazyMap` methods with nested `LazyCollection`s `V`
impl<K, V> LazyMap<K, V>
where
    K: storage::KeySeg,
    V: LazyCollection,
{
    /// Get a nested collection at given key `key`. If there is no nested
    /// collection at the given key, a new empty one will be provided. The
    /// nested collection may be manipulated through its methods.
    pub fn at(&self, key: &K) -> V {
        V::new(self.get_data_key(key))
    }
}

// `LazyMap` methods with borsh encoded values `V`
impl<K, V> LazyMap<K, V>
where
    K: storage::KeySeg,
    V: BorshDeserialize + BorshSerialize + 'static,
{
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
        S: StorageWrite + for<'iter> StorageRead<'iter>,
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
        let data_key = self.get_data_key(key);
        Self::read_key_val(storage, &data_key)
    }

    /// Returns whether the map contains no elements.
    pub fn is_empty<S>(&self, storage: &S) -> Result<bool>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let mut iter =
            storage_api::iter_prefix_bytes(storage, &self.get_data_prefix())?;
        Ok(iter.next().is_none())
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
    fn read_key_val<S>(
        storage: &S,
        storage_key: &storage::Key,
    ) -> Result<Option<V>>
    where
        S: for<'iter> StorageRead<'iter>,
    {
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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ledger::storage::testing::TestStorage;

    #[test]
    fn test_lazy_map_basics() -> storage_api::Result<()> {
        let mut storage = TestStorage::default();

        let key = storage::Key::parse("test").unwrap();
        let lazy_map = LazyMap::<u32, String>::new(key);

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
