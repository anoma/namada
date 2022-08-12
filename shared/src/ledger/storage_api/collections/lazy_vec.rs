//! Lazy vec

use std::marker::PhantomData;

use borsh::{BorshSerialize, BorshDeserialize};
use crate::{types::{storage}, ledger::storage_api::{StorageWrite, StorageRead}};
use super::super::Result;

/// Subkey pointing to the length of the LazyVec
pub const LEN_SUBKEY: &str = "len";
/// Subkey corresponding to the data elements of the LazyVec
pub const DATA_SUBKEY: &str = "data";

/// LazyVec ! fill in !
pub struct LazyVec<T> {
    key: storage::Key,
    phantom: PhantomData<T>,
}


impl<T> LazyVec<T> where T: BorshSerialize + BorshDeserialize {

    /// new
    pub fn new(key: storage::Key) -> Self {
        Self { key, phantom: PhantomData}
    }

    /// push
    pub fn push(&self, val: T, storage_read: &impl StorageRead, storage_write: &mut impl StorageWrite) -> Result<()> {
        let len = self.read_len(storage_read)?;

        let sub_index = len.unwrap_or(0);
        let len = sub_index + 1;

        let data_key = self.get_data_key(sub_index);

        storage_write.write(&data_key, val)?;
        storage_write.write(&self.get_len_key(), len)?;
        
        Ok(())
    }

    /// pop
    pub fn pop(&self, storage_read: &impl StorageRead, storage_write: &mut impl StorageWrite) -> Result<Option<T>> {
        let len = self.read_len(storage_read)?;
        match len {
            Some(0) | None => Ok(None),
            Some(len) => {
                let sub_index = len - 1;
                let data_key = self.get_data_key(sub_index);
                if len == 1 {
                    storage_write.delete(&self.get_len_key())?;

                } else {
                    storage_write.write(&self.get_len_key(), sub_index)?;

                }
                let popped_val = storage_read.read(&data_key)?;
                storage_write.delete(&data_key)?;
                Ok(popped_val)
            },
        }
        
    }

    /// get the length subkey
    fn get_len_key(&self) -> storage::Key {
        self.key.push(&LEN_SUBKEY.to_owned()).unwrap()
    }

    /// read the length of the LazyVec
    pub fn read_len(&self, storage_read: &impl StorageRead) -> Result<Option<u64>> {
        storage_read.read(&self.get_len_key())
    }

    /// get the data subkey
    fn get_data_key(&self, sub_index: u64) -> storage::Key {
        self.key.push(&DATA_SUBKEY.to_owned()).unwrap().push(&sub_index.to_string()).unwrap()
    }

    /// get the data held at a specific index within the data subkey
    fn get(&self, sub_index: u64, storage_read: &impl StorageRead) -> Result<Option<T>> {
        storage_read.read(&self.get_data_key(sub_index))
    }

}