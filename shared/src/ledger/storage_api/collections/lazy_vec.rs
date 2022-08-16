//! Lazy dynamically-sized vector.

use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};

use super::super::Result;
use crate::ledger::storage_api::{self, StorageRead, StorageWrite};
use crate::types::storage;

/// Subkey pointing to the length of the LazyVec
pub const LEN_SUBKEY: &str = "len";
/// Subkey corresponding to the data elements of the LazyVec
pub const DATA_SUBKEY: &str = "data";

/// Lazy dynamically-sized vector.
///
/// This can be used as an alternative to `std::collections::Vec`. In the lazy
/// vector, the elements do not reside in memory but are instead read and
/// written to storage sub-keys of the storage `key` used to construct the
/// vector.
pub struct LazyVec<T> {
    key: storage::Key,
    phantom: PhantomData<T>,
}

impl<T> LazyVec<T>
where
    T: BorshSerialize + BorshDeserialize + 'static,
{
    /// Create or use an existing vector with the given storage `key`.
    pub fn new(key: storage::Key) -> Self {
        Self {
            key,
            phantom: PhantomData,
        }
    }

    /// Appends an element to the back of a collection.
    pub fn push<S>(&self, storage: &mut S, val: T) -> Result<()>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let len = self.len(storage)?;
        let data_key = self.get_data_key(len);
        storage.write(&data_key, val)?;
        storage.write(&self.get_len_key(), len + 1)
    }

    /// Removes the last element from a vector and returns it, or `Ok(None)` if
    /// it is empty.
    ///
    /// Note that an empty vector is completely removed from storage.
    pub fn pop<S>(&self, storage: &mut S) -> Result<Option<T>>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let len = self.len(storage)?;
        if len == 0 {
            Ok(None)
        } else {
            let index = len - 1;
            let data_key = self.get_data_key(index);
            if len == 1 {
                storage.delete(&self.get_len_key())?;
            } else {
                storage.write(&self.get_len_key(), index)?;
            }
            let popped_val = storage.read(&data_key)?;
            storage.delete(&data_key)?;
            Ok(popped_val)
        }
    }

    /// Read an element at the index or `Ok(None)` if out of bounds.
    pub fn get<S>(&self, storage: &S, index: u64) -> Result<Option<T>>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        storage.read(&self.get_data_key(index))
    }

    /// Reads the number of elements in the vector.
    #[allow(clippy::len_without_is_empty)]
    pub fn len<S>(&self, storage: &S) -> Result<u64>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let len = storage.read(&self.get_len_key())?;
        Ok(len.unwrap_or_default())
    }

    /// Returns `true` if the vector contains no elements.
    pub fn is_empty<S>(&self, storage: &S) -> Result<bool>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        Ok(self.len(storage)? == 0)
    }

    /// An iterator visiting all elements. The iterator element type is
    /// `Result<T>`, because iterator's call to `next` may fail with e.g. out of
    /// gas or data decoding error.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded sets to avoid gas usage increasing with the length of the
    /// set.
    pub fn iter<'iter>(
        &self,
        storage: &'iter impl StorageRead<'iter>,
    ) -> Result<impl Iterator<Item = Result<T>> + 'iter> {
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

    /// Get the sub-key of vector's elements storage
    fn get_data_key(&self, index: u64) -> storage::Key {
        self.get_data_prefix().push(&index.to_string()).unwrap()
    }

    /// Get the sub-key of vector's length storage
    fn get_len_key(&self) -> storage::Key {
        self.key.push(&LEN_SUBKEY.to_owned()).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ledger::storage::testing::TestStorage;

    #[test]
    fn test_lazy_vec_basics() -> storage_api::Result<()> {
        let mut storage = TestStorage::default();

        let key = storage::Key::parse("test").unwrap();
        let lazy_vec = LazyVec::<u32>::new(key);

        // The vec should be empty at first
        assert!(lazy_vec.is_empty(&storage)?);
        assert!(lazy_vec.len(&storage)? == 0);
        assert!(lazy_vec.iter(&storage)?.next().is_none());
        assert!(lazy_vec.pop(&mut storage)?.is_none());
        assert!(lazy_vec.get(&storage, 0)?.is_none());
        assert!(lazy_vec.get(&storage, 1)?.is_none());

        // Push a new value and check that it's added
        lazy_vec.push(&mut storage, 15_u32)?;
        assert!(!lazy_vec.is_empty(&storage)?);
        assert!(lazy_vec.len(&storage)? == 1);
        assert_eq!(lazy_vec.iter(&storage)?.next().unwrap()?, 15_u32);
        assert_eq!(lazy_vec.get(&storage, 0)?.unwrap(), 15_u32);
        assert!(lazy_vec.get(&storage, 1)?.is_none());

        // Pop the last value and check that the vec is empty again
        let popped = lazy_vec.pop(&mut storage)?.unwrap();
        assert_eq!(popped, 15_u32);
        assert!(lazy_vec.is_empty(&storage)?);
        assert!(lazy_vec.len(&storage)? == 0);
        assert!(lazy_vec.iter(&storage)?.next().is_none());
        assert!(lazy_vec.pop(&mut storage)?.is_none());
        assert!(lazy_vec.get(&storage, 0)?.is_none());
        assert!(lazy_vec.get(&storage, 1)?.is_none());

        Ok(())
    }
}
