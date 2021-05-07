use std::collections::HashMap;

use anoma_shared::types::address::EstablishedAddressGen;
use anoma_shared::types::{Address, Key};
use thiserror::Error;

use crate::shell::storage::{self, PersistentStorage};

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
    InitAccount { vp: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct WriteLog {
    address_gen: Option<EstablishedAddressGen>,
    block_write_log: HashMap<Key, StorageModification>,
    tx_write_log: HashMap<Key, StorageModification>,
}

impl WriteLog {
    pub fn new() -> Self {
        Self {
            address_gen: None,
            block_write_log: HashMap::with_capacity(100_000),
            tx_write_log: HashMap::with_capacity(100),
        }
    }
}

impl WriteLog {
    /// Read a value at the given key and return the value and the gas cost,
    /// returns [`None`] if the key is not present in the write log
    pub fn read(&self, key: &Key) -> (Option<&StorageModification>, u64) {
        // try to read from tx write log first
        match self.tx_write_log.get(&key).or_else(|| {
            // if not found, then try to read from block write log
            self.block_write_log.get(&key)
        }) {
            Some(v) => {
                let gas = match v {
                    StorageModification::Write { ref value } => {
                        key.len() + value.len()
                    }
                    StorageModification::Delete => key.len(),
                    StorageModification::InitAccount { ref vp } => {
                        key.len() + vp.len()
                    }
                };
                (Some(v), gas as _)
            }
            None => (None, key.len() as _),
        }
    }

    /// Write a key and a value and return the gas cost and the size difference
    pub fn write(&mut self, key: &Key, value: Vec<u8>) -> (u64, i64) {
        let len = value.len();
        let gas = key.len() + len;
        let size_diff = match self
            .tx_write_log
            .insert(key.clone(), StorageModification::Write { value })
        {
            Some(prev) => match prev {
                StorageModification::Write { ref value } => {
                    len as i64 - value.len() as i64
                }
                StorageModification::Delete => len as i64,
                StorageModification::InitAccount { .. } => 0,
            },
            // set just the length of the value because we don't know if
            // the previous value exists on the storage
            None => len as i64,
        };
        (gas as _, size_diff)
    }

    /// Delete a key and its value, and return the gas cost and the size
    /// difference
    pub fn delete(&mut self, key: &Key) -> (u64, i64) {
        let size_diff = match self
            .tx_write_log
            .insert(key.clone(), StorageModification::Delete)
        {
            Some(prev) => match prev {
                StorageModification::Write { ref value } => value.len() as i64,
                StorageModification::Delete => 0,
                StorageModification::InitAccount { .. } => 0,
            },
            // set 0 because we don't know if the previous value exists on the
            // storage
            None => 0,
        };
        let gas = key.len() + (-size_diff as usize);
        (gas as _, size_diff)
    }

    /// Initialize a new account and return the gas cost.
    pub fn init_account(
        &mut self,
        storage_address_gen: &EstablishedAddressGen,
        vp: Vec<u8>,
    ) -> (Address, u64) {
        // If we've previously generated a new account, we use the local copy of the generator. Otherwise, we create a new copy from the storage
        let address_gen =
            self.address_gen.get_or_insert(storage_address_gen.clone());
        let addr =
            address_gen.generate_address("TODO more randomness".as_bytes());
        let key = Key::validity_predicate(&addr)
            .expect("Unable to create a validity predicate key");
        let gas = (key.len() + vp.len()) as _;
        self.tx_write_log
            .insert(key, StorageModification::InitAccount { vp });
        (addr, gas)
    }

    /// Get the storage keys changed in the current transaction
    pub fn get_changed_keys(&self) -> Vec<&Key> {
        self.tx_write_log
            .iter()
            .filter_map(|(key, value)| match value {
                StorageModification::InitAccount { .. } => None,
                _ => Some(key),
            })
            .collect()
    }

    /// Get the keys to the accounts initialized in the current transaction.
    /// The keys point to the validity predicates of the newly created accounts.
    pub fn get_initialized_accounts(&self) -> Vec<&Key> {
        self.tx_write_log
            .iter()
            .filter_map(|(key, value)| match value {
                StorageModification::InitAccount { .. } => Some(key),
                _ => None,
            })
            .collect()
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
    pub fn commit_block(
        &mut self,
        storage: &mut PersistentStorage,
    ) -> Result<()> {
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
                StorageModification::InitAccount { vp } => {
                    storage
                        .write(key, vp.clone())
                        .map_err(Error::StorageError)?;
                }
            }
        }
        if let Some(address_gen) = self.address_gen.take() {
            storage.address_gen = address_gen
        }
        self.block_write_log.clear();
        Ok(())
    }
}
