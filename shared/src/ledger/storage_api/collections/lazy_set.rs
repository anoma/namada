//! Lazy hash set

use std::{marker::PhantomData, hash::Hash, hash::Hasher};
use borsh::{BorshSerialize, BorshDeserialize};
use std::collections::hash_map::DefaultHasher;

use crate::{types::{storage}, ledger::storage_api::{StorageWrite, StorageRead}};
use super::super::Result;

/// Subkey corresponding to the data elements of the LazyVec
pub const DATA_SUBKEY: &str = "data";

/// lazy hash set
pub struct LazySet<T> {
    key: storage::Key,
    phantom: PhantomData<T>
}

impl<T> LazySet<T> where T: BorshSerialize + BorshDeserialize + Hash {

    /// new
    pub fn new(key: storage::Key) -> Self {
        Self { key, phantom: PhantomData}
    } 

    /// insert
    pub fn insert(&self, val: &T, storage_write: &mut impl StorageWrite) -> Result<()> {
        
        // Do we need to read to see if this val is already in the set?

        let data_key = self.get_data_key(val);
        storage_write.write(&data_key, &val)?;
        Ok(())
    }

    /// remove
    pub fn remove(&self, val: &T, storage_write: &mut impl StorageWrite) -> Result<()> {
        let data_key = self.get_data_key(val);
        storage_write.delete(&data_key)?;
        Ok(())
    }

    /// check if the hash set contains a value
    pub fn contains(&self, val: &T, storage_read: &impl StorageRead) -> Result<bool> {
        let digest: Option<T> = storage_read.read(&self.get_data_key(val))?;
        match digest {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    /// check if hash set is empty
    pub fn is_empty(&self) {
        todo!();
    }

    fn hash_val(&self, val: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        val.hash(&mut hasher);
        hasher.finish()
    }

        /// get the data subkey
    fn get_data_key(&self, val: &T) -> storage::Key {
        let hash_str = self.hash_val(val).to_string();
        self.key.push(&DATA_SUBKEY.to_owned()).unwrap().push(&hash_str).unwrap()
    }

}