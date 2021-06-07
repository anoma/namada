//! Write log is temporary storage for modifications performed by a transaction.
//! before they are committed to the ledger's storage.

use std::collections::HashMap;

use thiserror::Error;

use crate::ledger::storage::{self, Storage, StorageHasher};
use crate::types::address::EstablishedAddressGen;
use crate::types::{Address, Key};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Storage error applying a write log: {0}")]
    StorageError(storage::Error),
}

/// Result for functions that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// A storage modification
#[derive(Clone, Debug)]
pub enum StorageModification {
    /// Write a new value
    Write {
        /// Value bytes
        value: Vec<u8>,
    },
    /// Delete an existing key-value
    Delete,
    /// Initialize a new account with established address and a given validity
    /// predicate
    InitAccount {
        /// Validity predicate bytes
        vp: Vec<u8>,
    },
}

/// The write log storage
#[derive(Debug, Clone)]
pub struct WriteLog {
    /// The generator of established addresses
    address_gen: Option<EstablishedAddressGen>,
    /// All the storage modification accepted by validity predicates are stored
    /// in block write-log, before being committed to the storage
    block_write_log: HashMap<Key, StorageModification>,
    /// The storage modifications for the current transaction
    tx_write_log: HashMap<Key, StorageModification>,
}

impl Default for WriteLog {
    fn default() -> Self {
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
                StorageModification::InitAccount { .. } => {
                    tracing::info!(
                        "Trying to update the validity predicate that is just \
                         initialized"
                    );
                    unreachable!()
                }
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
                StorageModification::InitAccount { .. } => {
                    tracing::info!(
                        "Trying to delete the validity predicate that is just \
                         initialized"
                    );
                    unreachable!()
                }
            },
            // set 0 because we don't know if the previous value exists on the
            // storage
            None => 0,
        };
        let gas = key.len() + size_diff as usize;
        (gas as _, -size_diff)
    }

    /// Initialize a new account and return the gas cost.
    pub fn init_account(
        &mut self,
        storage_address_gen: &EstablishedAddressGen,
        vp: Vec<u8>,
    ) -> (Address, u64) {
        // If we've previously generated a new account, we use the local copy of
        // the generator. Otherwise, we create a new copy from the storage
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

    /// Get the storage keys changed and accounts keys initialized in the
    /// current transaction. The account keys point to the validity predicates
    /// of the newly created accounts.
    pub fn get_keys(&self) -> Vec<Key> {
        self.tx_write_log.keys().cloned().collect()
    }

    /// Get the storage keys changed in the current transaction (left) and
    /// the keys to the accounts initialized in the current transaction (right).
    /// The first vector excludes keys of validity predicates of newly
    /// initialized accounts, but may include keys of other data written
    /// into newly initialized accounts. The accounts keys point to the validity
    /// predicates of the newly created accounts.
    pub fn get_partitioned_keys(&self) -> (Vec<&Key>, Vec<&Key>) {
        use itertools::{Either, Itertools};
        self.tx_write_log
            .iter()
            .partition_map(|(key, value)| match value {
                StorageModification::InitAccount { .. } => Either::Right(key),
                _ => Either::Left(key),
            })
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
    pub fn commit_block<DB, H>(
        &mut self,
        storage: &mut Storage<DB, H>,
    ) -> Result<()>
    where
        DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
        H: StorageHasher,
    {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crud_value() {
        let mut write_log = WriteLog::default();
        let key =
            Key::parse("key".to_owned()).expect("cannot parse the key string");

        // read a non-existing key
        let (value, gas) = write_log.read(&key);
        assert!(value.is_none());
        assert_eq!(gas, key.len() as u64);

        // delete a non-existing key
        let (gas, diff) = write_log.delete(&key);
        assert_eq!(gas, key.len() as u64);
        assert_eq!(diff, 0);

        // insert a value
        let inserted = "inserted".as_bytes().to_vec();
        let (gas, diff) = write_log.write(&key, inserted.clone());
        assert_eq!(gas, (key.len() + inserted.len()) as u64);
        assert_eq!(diff, inserted.len() as i64);

        // read the value
        let (value, gas) = write_log.read(&key);
        match value.expect("no read value") {
            StorageModification::Write { value } => {
                assert_eq!(*value, inserted)
            }
            _ => panic!("unexpected read result"),
        }
        assert_eq!(gas, (key.len() + inserted.len()) as u64);

        // update the value
        let updated = "updated".as_bytes().to_vec();
        let (gas, diff) = write_log.write(&key, updated.clone());
        assert_eq!(gas, (key.len() + updated.len()) as u64);
        assert_eq!(diff, updated.len() as i64 - inserted.len() as i64);

        // delete the key
        let (gas, diff) = write_log.delete(&key);
        assert_eq!(gas, (key.len() + updated.len()) as u64);
        assert_eq!(diff, -(updated.len() as i64));

        // delete the deleted key again
        let (gas, diff) = write_log.delete(&key);
        assert_eq!(gas, key.len() as u64);
        assert_eq!(diff, 0);

        // read the deleted key
        let (value, gas) = write_log.read(&key);
        match &value.expect("no read value") {
            StorageModification::Delete => {}
            _ => panic!("unexpected result"),
        }
        assert_eq!(gas, key.len() as u64);

        // insert again
        let reinserted = "reinserted".as_bytes().to_vec();
        let (gas, diff) = write_log.write(&key, reinserted.clone());
        assert_eq!(gas, (key.len() + reinserted.len()) as u64);
        assert_eq!(diff, reinserted.len() as i64);
    }

    #[test]
    fn test_crud_account() {
        let mut write_log = WriteLog::default();
        let address_gen = EstablishedAddressGen::new("test");

        // init
        let init_vp = "initialized".as_bytes().to_vec();
        let (addr, gas) = write_log.init_account(&address_gen, init_vp.clone());
        let vp_key =
            Key::validity_predicate(&addr).expect("cannot create the vp key");
        assert_eq!(gas, (vp_key.len() + init_vp.len()) as u64);

        // read
        let (value, gas) = write_log.read(&vp_key);
        match value.expect("no read value") {
            StorageModification::InitAccount { vp } => assert_eq!(*vp, init_vp),
            _ => panic!("unexpected result"),
        }
        assert_eq!(gas, (vp_key.len() + init_vp.len()) as u64);

        // get all
        let (_changed_keys, accounts) = write_log.get_partitioned_keys();
        assert!(accounts.contains(&&vp_key));
        assert_eq!(accounts.len(), 1);
    }

    #[test]
    #[should_panic]
    fn test_update_initialized_account() {
        let mut write_log = WriteLog::default();
        let address_gen = EstablishedAddressGen::new("test");

        let init_vp = "initialized".as_bytes().to_vec();
        let (addr, _) = write_log.init_account(&address_gen, init_vp);
        let vp_key =
            Key::validity_predicate(&addr).expect("cannot create the vp key");

        // update should fail
        let updated_vp = "updated".as_bytes().to_vec();
        write_log.write(&vp_key, updated_vp);
    }

    #[test]
    #[should_panic]
    fn test_delete_initialized_account() {
        let mut write_log = WriteLog::default();
        let address_gen = EstablishedAddressGen::new("test");

        let init_vp = "initialized".as_bytes().to_vec();
        let (addr, _) = write_log.init_account(&address_gen, init_vp);
        let vp_key =
            Key::validity_predicate(&addr).expect("cannot create the vp key");

        // delete should fail
        write_log.delete(&vp_key);
    }

    #[test]
    fn test_commit() {
        let mut storage =
            crate::ledger::storage::testing::TestStorage::default();
        let mut write_log = WriteLog::default();
        let address_gen = EstablishedAddressGen::new("test");

        let key1 =
            Key::parse("key1".to_owned()).expect("cannot parse the key string");
        let key2 =
            Key::parse("key2".to_owned()).expect("cannot parse the key string");
        let key3 =
            Key::parse("key3".to_owned()).expect("cannot parse the key string");

        // initialize an account
        let vp1 = "vp1".as_bytes().to_vec();
        let (addr1, _) = write_log.init_account(&address_gen, vp1.clone());
        write_log.commit_tx();

        // write values
        let val1 = "val1".as_bytes().to_vec();
        write_log.write(&key1, val1.clone());
        write_log.write(&key2, val1.clone());
        write_log.write(&key3, val1.clone());
        write_log.commit_tx();

        // these values are not written due to drop_tx
        let val2 = "val2".as_bytes().to_vec();
        write_log.write(&key1, val2.clone());
        write_log.write(&key2, val2.clone());
        write_log.write(&key3, val2);
        write_log.drop_tx();

        // deletes and updates values
        let val3 = "val3".as_bytes().to_vec();
        write_log.delete(&key2);
        write_log.write(&key3, val3.clone());
        write_log.commit_tx();

        // commit a block
        write_log.commit_block(&mut storage).expect("commit failed");

        let (vp, _gas) =
            storage.validity_predicate(&addr1).expect("vp read failed");
        assert_eq!(vp, Some(vp1));
        let (value, _) = storage.read(&key1).expect("read failed");
        assert_eq!(value.expect("no read value"), val1);
        let (value, _) = storage.read(&key2).expect("read failed");
        assert!(value.is_none());
        let (value, _) = storage.read(&key3).expect("read failed");
        assert_eq!(value.expect("no read value"), val3);
    }
}
