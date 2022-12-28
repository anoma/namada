//! Lazy map.

use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use thiserror::Error;

use super::super::Result;
use super::{LazyCollection, ReadError};
use crate::ledger::storage_api::validation::{self, Data};
use crate::ledger::storage_api::{self, ResultExt, StorageRead, StorageWrite};
use crate::ledger::vp_env::VpEnv;
use crate::types::storage::{self, DbKeySeg, KeySeg};

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
#[derive(Debug)]
pub struct LazyMap<K, V, SON = super::Simple> {
    key: storage::Key,
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,
    phantom_son: PhantomData<SON>,
}

/// A `LazyMap` with another `LazyCollection` inside it's value `V`
pub type NestedMap<K, V> = LazyMap<K, V, super::Nested>;

/// Possible sub-keys of a [`LazyMap`]
#[derive(Clone, Debug)]
pub enum SubKey<K> {
    /// Data sub-key, further sub-keyed by its literal map key
    Data(K),
}

/// Possible sub-keys of a [`LazyMap`], together with their [`validation::Data`]
/// that contains prior and posterior state.
#[derive(Clone, Debug)]
pub enum SubKeyWithData<K, V> {
    /// Data sub-key, further sub-keyed by its literal map key
    Data(K, Data<V>),
}

/// Possible actions that can modify a simple (not nested) [`LazyMap`]. This
/// roughly corresponds to the methods that have `StorageWrite` access.
#[derive(Clone, Debug)]
pub enum Action<K, V> {
    /// Insert or update a value `V` at key `K` in a [`LazyMap<K, V>`].
    Insert(K, V),
    /// Remove a value `V` at key `K` from a [`LazyMap<K, V>`].
    Remove(K, V),
    /// Update a value `V` at key `K` in a [`LazyMap<K, V>`].
    Update {
        /// key at which the value is updated
        key: K,
        /// value before the update
        pre: V,
        /// value after the update
        post: V,
    },
}

/// Possible actions that can modify a nested [`LazyMap`].
#[derive(Clone, Debug)]
pub enum NestedAction<K, A> {
    /// Nested collection action `A` at key `K`
    At(K, A),
}

/// Possible sub-keys of a nested [`LazyMap`]
#[derive(Clone, Debug)]
pub enum NestedSubKey<K, S> {
    /// Data sub-key
    Data {
        /// Literal map key
        key: K,
        /// Sub-key in the nested collection
        nested_sub_key: S,
    },
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Invalid storage key {0}")]
    InvalidSubKey(storage::Key),
    #[error("Invalid nested storage key {0}")]
    InvalidNestedSubKey(storage::Key),
}

/// [`LazyMap`] validation result
pub type ValidationResult<T> = std::result::Result<T, ValidationError>;

impl<K, V> LazyCollection for LazyMap<K, V, super::Nested>
where
    K: storage::KeySeg + Clone + Hash + Eq + Debug,
    V: LazyCollection + Debug,
{
    type Action = NestedAction<K, <V as LazyCollection>::Action>;
    type SubKey = NestedSubKey<K, <V as LazyCollection>::SubKey>;
    type SubKeyWithData =
        NestedSubKey<K, <V as LazyCollection>::SubKeyWithData>;
    type Value = <V as LazyCollection>::Value;

    fn open(key: storage::Key) -> Self {
        Self {
            key,
            phantom_k: PhantomData,
            phantom_v: PhantomData,
            phantom_son: PhantomData,
        }
    }

    fn is_valid_sub_key(
        &self,
        key: &storage::Key,
    ) -> storage_api::Result<Option<Self::SubKey>> {
        let suffix = match key.split_prefix(&self.key) {
            None => {
                // not matching prefix, irrelevant
                return Ok(None);
            }
            Some(None) => {
                // no suffix, invalid
                return Err(ValidationError::InvalidSubKey(key.clone()))
                    .into_storage_result();
            }
            Some(Some(suffix)) => suffix,
        };

        // Match the suffix against expected sub-keys
        match &suffix.segments[..2] {
            [DbKeySeg::StringSeg(sub_a), DbKeySeg::StringSeg(sub_b)]
                if sub_a == DATA_SUBKEY =>
            {
                if let Ok(key_in_kv) = storage::KeySeg::parse(sub_b.clone()) {
                    let nested = self.at(&key_in_kv).is_valid_sub_key(key)?;
                    match nested {
                        Some(nested_sub_key) => Ok(Some(NestedSubKey::Data {
                            key: key_in_kv,
                            nested_sub_key,
                        })),
                        None => Err(ValidationError::InvalidNestedSubKey(
                            key.clone(),
                        ))
                        .into_storage_result(),
                    }
                } else {
                    Err(ValidationError::InvalidSubKey(key.clone()))
                        .into_storage_result()
                }
            }
            _ => Err(ValidationError::InvalidSubKey(key.clone()))
                .into_storage_result(),
        }
    }

    fn read_sub_key_data<ENV>(
        env: &ENV,
        storage_key: &storage::Key,
        sub_key: Self::SubKey,
    ) -> storage_api::Result<Option<Self::SubKeyWithData>>
    where
        ENV: for<'a> VpEnv<'a>,
    {
        let NestedSubKey::Data {
            key,
            // In here, we just have a nested sub-key without data
            nested_sub_key,
        } = sub_key;
        // Try to read data from the nested collection
        let nested_data = <V as LazyCollection>::read_sub_key_data(
            env,
            storage_key,
            nested_sub_key,
        )?;
        // If found, transform it back into a `NestedSubKey`, but with
        // `nested_sub_key` replaced with the one we read
        Ok(nested_data.map(|nested_sub_key| NestedSubKey::Data {
            key,
            nested_sub_key,
        }))
    }

    fn validate_changed_sub_keys(
        keys: Vec<Self::SubKeyWithData>,
    ) -> storage_api::Result<Vec<Self::Action>> {
        // We have to group the nested sub-keys by the key from this map
        let mut grouped_by_key: HashMap<
            K,
            Vec<<V as LazyCollection>::SubKeyWithData>,
        > = HashMap::new();
        for NestedSubKey::Data {
            key,
            nested_sub_key,
        } in keys
        {
            grouped_by_key
                .entry(key)
                .or_insert_with(Vec::new)
                .push(nested_sub_key);
        }

        // Recurse for each sub-keys group
        let mut actions = vec![];
        for (key, sub_keys) in grouped_by_key {
            let nested_actions =
                <V as LazyCollection>::validate_changed_sub_keys(sub_keys)?;
            actions.extend(
                nested_actions
                    .into_iter()
                    .map(|action| NestedAction::At(key.clone(), action)),
            );
        }
        Ok(actions)
    }
}

impl<K, V> LazyCollection for LazyMap<K, V, super::Simple>
where
    K: storage::KeySeg + Debug,
    V: BorshDeserialize + BorshSerialize + 'static + Debug,
{
    type Action = Action<K, V>;
    type SubKey = SubKey<K>;
    type SubKeyWithData = SubKeyWithData<K, V>;
    type Value = V;

    /// Create or use an existing map with the given storage `key`.
    fn open(key: storage::Key) -> Self {
        Self {
            key,
            phantom_k: PhantomData,
            phantom_v: PhantomData,
            phantom_son: PhantomData,
        }
    }

    fn is_valid_sub_key(
        &self,
        key: &storage::Key,
    ) -> storage_api::Result<Option<Self::SubKey>> {
        let suffix = match key.split_prefix(&self.key) {
            None => {
                // not matching prefix, irrelevant
                return Ok(None);
            }
            Some(None) => {
                // no suffix, invalid
                return Err(ValidationError::InvalidSubKey(key.clone()))
                    .into_storage_result();
            }
            Some(Some(suffix)) => suffix,
        };

        // Match the suffix against expected sub-keys
        match &suffix.segments[..] {
            [DbKeySeg::StringSeg(sub_a), DbKeySeg::StringSeg(sub_b)]
                if sub_a == DATA_SUBKEY =>
            {
                if let Ok(key_in_kv) = storage::KeySeg::parse(sub_b.clone()) {
                    Ok(Some(SubKey::Data(key_in_kv)))
                } else {
                    Err(ValidationError::InvalidSubKey(key.clone()))
                        .into_storage_result()
                }
            }
            _ => Err(ValidationError::InvalidSubKey(key.clone()))
                .into_storage_result(),
        }
    }

    fn read_sub_key_data<ENV>(
        env: &ENV,
        storage_key: &storage::Key,
        sub_key: Self::SubKey,
    ) -> storage_api::Result<Option<Self::SubKeyWithData>>
    where
        ENV: for<'a> VpEnv<'a>,
    {
        let SubKey::Data(key) = sub_key;
        let data = validation::read_data(env, storage_key)?;
        Ok(data.map(|data| SubKeyWithData::Data(key, data)))
    }

    fn validate_changed_sub_keys(
        keys: Vec<Self::SubKeyWithData>,
    ) -> storage_api::Result<Vec<Self::Action>> {
        Ok(keys
            .into_iter()
            .map(|change| {
                let SubKeyWithData::Data(key, data) = change;
                match data {
                    Data::Add { post } => Action::Insert(key, post),
                    Data::Update { pre, post } => {
                        Action::Update { key, pre, post }
                    }
                    Data::Delete { pre } => Action::Remove(key, pre),
                }
            })
            .collect())
    }
}

// Generic `LazyMap` methods that require no bounds on values `V`
impl<K, V, SON> LazyMap<K, V, SON>
where
    K: storage::KeySeg,
{
    /// Returns whether the set contains a value.
    pub fn contains<S>(&self, storage: &S, key: &K) -> Result<bool>
    where
        S: StorageRead,
    {
        storage.has_key(&self.get_data_key(key))
    }

    /// Get the prefix of set's elements storage
    fn get_data_prefix(&self) -> storage::Key {
        self.key.push(&DATA_SUBKEY.to_owned()).unwrap()
    }

    /// Get the sub-key of a given element
    pub fn get_data_key(&self, key: &K) -> storage::Key {
        let key_str = key.to_db_key();
        self.get_data_prefix().push(&key_str).unwrap()
    }
}

// `LazyMap` methods with nested `LazyCollection`s `V`
impl<K, V> LazyMap<K, V, super::Nested>
where
    K: storage::KeySeg + Clone + Hash + Eq + Debug,
    V: LazyCollection + Debug,
{
    /// Get a nested collection at given key `key`. If there is no nested
    /// collection at the given key, a new empty one will be provided. The
    /// nested collection may be manipulated through its methods.
    pub fn at(&self, key: &K) -> V {
        V::open(self.get_data_key(key))
    }

    /// An iterator visiting all key-value elements, where the values are from
    /// the inner-most collection. The iterator element type is `Result<_>`,
    /// because iterator's call to `next` may fail with e.g. out of gas or
    /// data decoding error.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded maps to avoid gas usage increasing with the length of the
    /// map.
    pub fn iter<'iter>(
        &'iter self,
        storage: &'iter impl StorageRead,
    ) -> Result<
        impl Iterator<
            Item = Result<(
                <Self as LazyCollection>::SubKey,
                <Self as LazyCollection>::Value,
            )>,
        > + 'iter,
    > {
        let iter = storage_api::iter_prefix(storage, &self.get_data_prefix())?;
        Ok(iter.map(|key_val_res| {
            let (key, val) = key_val_res?;
            let sub_key = LazyCollection::is_valid_sub_key(self, &key)?
                .ok_or(ReadError::UnexpectedlyEmptyStorageKey)
                .into_storage_result()?;
            Ok((sub_key, val))
        }))
    }

    /// Returns whether the map contains no elements.
    pub fn is_empty<S>(&self, storage: &S) -> Result<bool>
    where
        S: StorageRead,
    {
        let mut iter =
            storage_api::iter_prefix_bytes(storage, &self.get_data_prefix())?;
        Ok(iter.next().is_none())
    }
}

// `LazyMap` methods with borsh encoded values `V`
impl<K, V> LazyMap<K, V, super::Simple>
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
    pub fn get<S>(&self, storage: &S, key: &K) -> Result<Option<V>>
    where
        S: StorageRead,
    {
        let data_key = self.get_data_key(key);
        Self::read_key_val(storage, &data_key)
    }

    /// Returns whether the map contains no elements.
    pub fn is_empty<S>(&self, storage: &S) -> Result<bool>
    where
        S: StorageRead,
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
        S: StorageRead,
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
        storage: &'iter impl StorageRead,
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
        S: StorageRead,
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
        let lazy_map = LazyMap::<u32, String>::open(key);

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
