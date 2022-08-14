//! Lazy map

use borsh::{BorshSerialize, BorshDeserialize};
use std::{marker::PhantomData, hash::Hash, hash::Hasher};
use std::collections::hash_map::DefaultHasher;

use crate::{types::{storage}, ledger::storage_api::{StorageWrite, StorageRead}};
use super::super::Result;


/// Subkey corresponding to the data elements of the LazyMap
pub const DATA_SUBKEY: &str = "data";

/// LazyMap ! fill in !
pub struct LazyMap<H, T> {
    key: storage::Key,
    phantom_h: PhantomData<H>,
    phantom_t: PhantomData<T>
}

impl<H, T> LazyMap<H, T> where H: BorshDeserialize + BorshSerialize + Hash,
T: BorshDeserialize + BorshSerialize {
    
    /// insert
    pub fn insert(&self, elem_key: &H, elem_val: T, storage_write: &mut impl StorageWrite) -> Result<()> {

        // TODO: Check to see if map element exists already ??

        let data_key = self.get_data_key(elem_key);
        storage_write.write(&data_key, (elem_key, elem_val))?;


        Ok(())
    }

    /// remove
    pub fn remove(&self, elem_key: &H, storage_write: &mut impl StorageWrite) -> Result<()> {
        
        let data_key = self.get_data_key(elem_key);
        storage_write.delete(&data_key)?;

        Ok(())
    }

    /// get value
    pub fn get_val(&self, elem_key: &H, storage_read: &mut impl StorageRead) -> Result<Option<T>> {
        
        // check if elem_key exists in the first place?

        let data_key = self.get_data_key(elem_key);
        storage_read.read(&data_key)

    }

    /// hash
    fn hash(&self, elem_key: &H) -> u64 {
        let mut hasher = DefaultHasher::new();
        elem_key.hash(&mut hasher);
        hasher.finish()
    }

    /// get the data subkey
    fn get_data_key(&self, elem_key: &H) -> storage::Key {
        let hash_str = self.hash(elem_key).to_string();
        self.key.push(&DATA_SUBKEY.to_owned()).unwrap().push(&hash_str).unwrap()
    }

}