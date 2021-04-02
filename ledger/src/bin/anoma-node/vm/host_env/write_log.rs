use std::collections::HashMap;

use thiserror::Error;

use crate::shell::storage::{self, Address, Storage};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Storage error applying a write log: {0}")]
    StorageError(storage::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

// TODO some form of this will be in storage module
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StorageKey {
    pub addr: Address,
    pub key: String,
}

#[derive(Clone, Debug)]
pub enum StorageModification {
    Write { value: Vec<u8> },
    Delete,
}

#[derive(Debug)]
pub struct WriteLog {
    block_write_log: HashMap<StorageKey, StorageModification>,
    tx_write_log: HashMap<StorageKey, StorageModification>,
}

impl WriteLog {
    pub fn new() -> Self {
        Self {
            block_write_log: HashMap::with_capacity(100_000),
            tx_write_log: HashMap::with_capacity(100),
        }
    }
}

impl WriteLog {
    /// Read a value at the given key, returns [`None`] if the key is not
    /// present in the write log
    pub fn read<K>(
        &self,
        addr: &Address,
        key: K,
    ) -> Option<&StorageModification>
    where
        K: AsRef<str>,
    {
        let s_key = StorageKey {
            addr: addr.clone(),
            key: key.as_ref().to_string(),
        };
        // try to read from tx write log first
        self.tx_write_log.get(&s_key).or_else(|| {
            // if not found, then try to read from block write log
            self.block_write_log.get(&s_key)
        })
    }

    /// Write a key and a value
    pub fn write(&mut self, addr: Address, key: String, value: Vec<u8>) {
        self.tx_write_log.insert(
            StorageKey { addr, key },
            StorageModification::Write { value },
        );
    }

    /// Delete a key and its value
    pub fn delete(&mut self, addr: Address, key: String) {
        self.tx_write_log
            .insert(StorageKey { addr, key }, StorageModification::Delete);
    }

    pub fn get_changed_keys(&self) -> Vec<&StorageKey> {
        self.tx_write_log.keys().collect()
    }

    /// Commit the current transaction's write log to the block when it's
    /// accepted by all the triggered validity predicates. Starts a new
    /// transaction write log.
    pub fn commit_tx(&mut self) {
        let tx_write_log = std::mem::replace(
            &mut self.tx_write_log,
            HashMap::with_capacity(100),
        );
        self.block_write_log.extend(tx_write_log);
    }

    /// Drop the current transaction's write log when it's declined by any of
    /// the triggered validity predicates. Starts a new transaction write log.
    pub fn drop_tx(&mut self) {
        self.tx_write_log.clear();
    }

    /// Commit the current block's write log to the storage. Starts a new block
    /// write log.
    pub fn commit_block(&mut self, storage: &mut Storage) -> Result<()> {
        for (StorageKey { addr, key }, entry) in self.block_write_log.iter() {
            match entry {
                StorageModification::Write { value } => {
                    storage
                        .write(addr, key, value.clone())
                        .map_err(Error::StorageError)?;
                }
                StorageModification::Delete => {
                    storage.delete(addr, key).map_err(Error::StorageError)?;
                }
            }
        }
        self.block_write_log.clear();
        Ok(())
    }
}
