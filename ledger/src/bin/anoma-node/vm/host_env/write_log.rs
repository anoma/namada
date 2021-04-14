use std::collections::HashMap;

use thiserror::Error;

use crate::shell::storage::{self, Key, Storage};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Storage error applying a write log: {0}")]
    StorageError(storage::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub enum StorageModification {
    Write { value: Vec<u8> },
    Delete,
}

#[derive(Debug, Clone)]
pub struct WriteLog {
    block_write_log: HashMap<Key, StorageModification>,
    tx_write_log: HashMap<Key, StorageModification>,
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
    pub fn read(&self, key: &Key) -> Option<&StorageModification> {
        // try to read from tx write log first
        self.tx_write_log.get(&key).or_else(|| {
            // if not found, then try to read from block write log
            self.block_write_log.get(&key)
        })
    }

    /// Write a key and a value
    pub fn write(&mut self, key: &Key, value: Vec<u8>) {
        self.tx_write_log
            .insert(key.clone(), StorageModification::Write { value });
    }

    /// Delete a key and its value
    pub fn delete(&mut self, key: &Key) {
        self.tx_write_log
            .insert(key.clone(), StorageModification::Delete);
    }

    pub fn get_changed_keys(&self) -> Vec<&Key> {
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
        for (key, entry) in self.block_write_log.iter() {
            match entry {
                StorageModification::Write { value } => {
                    storage
                        .write(key, value.clone())
                        .map_err(Error::StorageError)?;
                }
                StorageModification::Delete => {
                    storage.delete(key).map_err(Error::StorageError)?;
                }
            }
        }
        self.block_write_log.clear();
        Ok(())
    }
}
