//! The storage module handles both the current state in-memory and the stored
//! state in DB.

pub mod db;
pub mod types;

use std::collections::HashMap;
use std::ops::Deref;
use std::path::Path;

use anoma_shared::types::address::EstablishedAddressGen;
use anoma_shared::types::{
    Address, BlockHash, BlockHeight, Key, BLOCK_HASH_LENGTH, CHAIN_ID_LENGTH,
};
pub use db::{DBIter, DB};
use sparse_merkle_tree::H256;
use thiserror::Error;
use types::MerkleTree;

use self::types::Hash256;
use super::MerkleRoot;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Key error {0}")]
    KeyError(anoma_shared::types::Error),
    #[error("Database error: {0}")]
    DBError(db::Error),
    #[error("Merkle tree error: {0}")]
    MerkleTreeError(sparse_merkle_tree::error::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

const MIN_STORAGE_GAS: u64 = 1;

#[derive(Debug)]
pub struct Storage<DB>
where
    DB: db::DB + for<'iter> DBIter<'iter>,
{
    db: DB,
    chain_id: String,
    // TODO Because the transaction may modify and state, we'll probably need
    // to split into read-only last block state and mutable current block state
    // for write-only. When the block is committed, the former will be updated
    // to the state of the latter
    block: BlockStorage,
    current_height: BlockHeight,
    pub(crate) address_gen: EstablishedAddressGen,
}

pub type PersistentStorage = Storage<db::rocksdb::RocksDB>;

#[derive(Debug)]
pub struct BlockStorage {
    tree: MerkleTree,
    hash: BlockHash,
    height: BlockHeight,
    subspaces: HashMap<Key, Vec<u8>>,
}

impl PersistentStorage {
    pub fn new(db_path: impl AsRef<Path>) -> Self {
        let tree = MerkleTree::default();
        let subspaces = HashMap::new();
        let block = BlockStorage {
            tree,
            hash: BlockHash::default(),
            height: BlockHeight(0),
            subspaces,
        };
        Self {
            db: db::rocksdb::open(db_path).expect("cannot open the DB"),
            chain_id: String::with_capacity(CHAIN_ID_LENGTH),
            block,
            current_height: BlockHeight(0),
            address_gen: EstablishedAddressGen::new(
                "Privacy is a function of liberty.",
            ),
        }
    }
}

impl<DB> Storage<DB>
where
    DB: db::DB + for<'iter> db::DBIter<'iter>,
{
    /// Load the full state at the last committed height, if any. Returns the
    /// Merkle root hash and the height of the committed block.
    pub fn load_last_state(&mut self) -> Result<Option<(MerkleRoot, u64)>> {
        if let Some(db::BlockState {
            chain_id,
            tree,
            hash,
            height,
            subspaces,
            address_gen,
        }) = self.db.read_last_block().map_err(Error::DBError)?
        {
            self.chain_id = chain_id;
            self.block.tree = tree;
            self.block.hash = hash;
            self.block.height = height;
            self.block.subspaces = subspaces;
            self.current_height = height;
            self.address_gen = address_gen;
            tracing::debug!("Loaded storage from DB");
            return Ok(Some((
                MerkleRoot(
                    self.block.tree.0.root().as_slice().deref().to_vec(),
                ),
                self.block.height.0,
            )));
        }
        Ok(None)
    }

    /// Persist the current block's state to the database
    pub fn commit(&mut self) -> Result<()> {
        // TODO DB sub-dir with chain ID?
        self.db
            .write_block(
                &self.block.tree,
                &self.block.hash,
                self.block.height,
                &self.block.subspaces,
                &self.address_gen,
            )
            .map_err(Error::DBError)?;
        self.current_height = self.block.height;
        Ok(())
    }

    /// # Storage reads
    pub fn merkle_root(&self) -> &H256 {
        self.block.tree.0.root()
    }

    /// # Storage writes
    // TODO Enforce or check invariant (it should catch newly added storage
    // fields too) that every function that changes storage, except for data
    // from Tendermint's block header should call this function to update the
    // Merkle tree.
    fn update_tree(&mut self, key: H256, value: H256) -> Result<()> {
        self.block
            .tree
            .0
            .update(key, value)
            .map_err(Error::MerkleTreeError)?;
        Ok(())
    }

    pub fn has_key(&self, key: &Key) -> Result<(bool, u64)> {
        let gas = key.len();
        Ok((
            !self
                .block
                .tree
                .0
                .get(&key.hash256())
                .map_err(Error::MerkleTreeError)?
                .is_zero(),
            gas as _,
        ))
    }

    /// Returns a value from the specified subspace and the gas cost
    pub fn read(&self, key: &Key) -> Result<(Option<Vec<u8>>, u64)> {
        let (present, gas) = self.has_key(key)?;
        if !present {
            return Ok((None, gas));
        }

        if let Some(v) = self.block.subspaces.get(key) {
            let gas = key.len() + v.len();
            return Ok((Some(v.to_vec()), gas as _));
        }

        match self
            .db
            .read(self.current_height, key)
            .map_err(Error::DBError)?
        {
            Some(v) => {
                let gas = key.len() + v.len();
                Ok((Some(v), gas as _))
            }
            None => Ok((None, key.len() as _)),
        }
    }

    /// Returns a prefix iterator and the gas cost
    pub fn iter_prefix(
        &self,
        prefix: &Key,
    ) -> (<DB as db::DBIter<'_>>::PrefixIter, u64) {
        (
            self.db.iter_prefix(self.current_height, prefix),
            prefix.len() as _,
        )
    }

    /// Write a value to the specified subspace and returns the gas cost and the
    /// size difference
    pub fn write(&mut self, key: &Key, value: Vec<u8>) -> Result<(u64, i64)> {
        self.update_tree(key.hash256(), value.hash256())?;

        let len = value.len();
        let gas = key.len() + len;
        let size_diff = match self.block.subspaces.insert(key.clone(), value) {
            Some(prev) => len as i64 - prev.len() as i64,
            None => len as i64,
        };
        Ok((gas as _, size_diff))
    }

    /// Delete the specified subspace and returns the gas cost and the size
    /// difference
    pub fn delete(&mut self, key: &Key) -> Result<(u64, i64)> {
        let mut size_diff = 0;
        if self.has_key(key)?.0 {
            // update the merkle tree with a zero as a tombstone
            self.update_tree(key.hash256(), H256::zero())?;

            size_diff -= match self.block.subspaces.remove(key) {
                Some(prev) => prev.len() as i64,
                None => 0,
            };
        }
        let gas = key.len() + (-size_diff as usize);
        Ok((gas as _, size_diff))
    }

    /// # Block header data
    /// Chain ID is not in the Merkle tree as it's tracked by Tendermint in the
    /// block header. Hence, we don't update the tree when this is set.
    pub fn set_chain_id(&mut self, chain_id: &str) -> Result<()> {
        if self.chain_id == chain_id {
            return Ok(());
        }
        self.chain_id = chain_id.to_owned();
        self.db
            .write_chain_id(&self.chain_id)
            .map_err(Error::DBError)?;
        Ok(())
    }

    /// Block data is in the Merkle tree as it's tracked by Tendermint in the
    /// block header. Hence, we don't update the tree when this is set.
    pub fn begin_block(
        &mut self,
        hash: BlockHash,
        height: BlockHeight,
    ) -> Result<()> {
        self.block.hash = hash;
        self.block.height = height;
        Ok(())
    }

    /// Get a validity predicate for the given account address and the gas cost
    /// for reading it.
    pub fn validity_predicate(
        &self,
        addr: &Address,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        let key = Key::validity_predicate(addr).map_err(Error::KeyError)?;
        self.read(&key)
    }

    #[allow(dead_code)]
    /// Check if the given address exists on chain and return the gas cost.
    pub fn exists(&self, addr: &Address) -> Result<(bool, u64)> {
        let key = Key::validity_predicate(addr).map_err(Error::KeyError)?;
        self.has_key(&key)
    }

    /// Get the chain ID
    pub fn get_chain_id(&self) -> (String, u64) {
        (self.chain_id.clone(), CHAIN_ID_LENGTH as _)
    }

    /// Get the current (yet to be committed) block height
    pub fn get_block_height(&self) -> (BlockHeight, u64) {
        (self.block.height, MIN_STORAGE_GAS)
    }

    /// Get the current (yet to be committed) block hash
    pub fn get_block_hash(&self) -> (BlockHash, u64) {
        (self.block.hash.clone(), BLOCK_HASH_LENGTH as _)
    }
}

#[cfg(test)]
mod tests {
    use tempdir::TempDir;

    use super::{types, *};

    #[test]
    fn test_crud_value() {
        let db_path = TempDir::new("anoma_test")
            .expect("Unable to create a temporary DB directory");
        let mut storage = PersistentStorage::new(db_path.path());
        let key =
            Key::parse("key".to_owned()).expect("cannot parse the key string");
        let value: u64 = 1;
        let value_bytes = types::encode(&value);
        let value_bytes_len = value_bytes.len();

        // before insertion
        let (result, gas) = storage.has_key(&key).expect("has_key failed");
        assert!(!result);
        assert_eq!(gas, key.len() as u64);
        let (result, gas) = storage.read(&key).expect("read failed");
        assert_eq!(result, None);
        assert_eq!(gas, key.len() as u64);

        // insert
        storage.write(&key, value_bytes).expect("write failed");

        // read
        let (result, gas) = storage.has_key(&key).expect("has_key failed");
        assert!(result);
        assert_eq!(gas, key.len() as u64);
        let (result, gas) = storage.read(&key).expect("read failed");
        let read_value: u64 =
            types::decode(&result.expect("value doesn't exist"))
                .expect("decoding failed");
        assert_eq!(read_value, value);
        assert_eq!(gas, key.len() as u64 + value_bytes_len as u64);

        // delete
        storage.delete(&key).expect("delete failed");

        // read again
        let (result, _) = storage.has_key(&key).expect("has_key failed");
        assert!(!result);
        let (result, _) = storage.read(&key).expect("read failed");
        assert_eq!(result, None);
    }

    #[test]
    fn test_commit_block() {
        let db_path = TempDir::new("anoma_test")
            .expect("Unable to create a temporary DB directory");
        let mut storage = PersistentStorage::new(db_path.path());
        let chain_id = "test_chain_id_000000";
        storage
            .set_chain_id(chain_id)
            .expect("setting a chain ID failed");
        storage
            .begin_block(BlockHash::default(), BlockHeight(100))
            .expect("begin_block failed");
        let key =
            Key::parse("key".to_owned()).expect("cannot parse the key string");
        let value: u64 = 1;
        let value_bytes = types::encode(&value);

        // insert and commit
        storage
            .write(&key, value_bytes.clone())
            .expect("write failed");
        storage.commit().expect("commit failed");

        // save the last state and drop the storage
        let root = storage.merkle_root().as_slice().deref().to_vec();
        let hash = storage.get_block_hash().0;
        let address_gen = storage.address_gen.clone();
        drop(storage);

        // load the last state
        let mut storage = PersistentStorage::new(db_path.path());
        let (loaded_root, height) = storage
            .load_last_state()
            .expect("loading the last state failed")
            .expect("no block exists");
        assert_eq!(loaded_root.0, root);
        assert_eq!(height, 100);
        assert_eq!(storage.get_chain_id().0, chain_id);
        assert_eq!(storage.get_block_hash().0, hash);
        assert_eq!(storage.address_gen, address_gen);
        let (val, _) = storage.read(&key).expect("read failed");
        assert_eq!(val.expect("no value"), value_bytes);
    }

    #[test]
    fn test_iter() {
        let db_path = TempDir::new("anoma_test")
            .expect("Unable to create a temporary DB directory");
        let mut storage = PersistentStorage::new(db_path.path());
        storage
            .begin_block(BlockHash::default(), BlockHeight(100))
            .expect("begin_block failed");

        let mut expected = Vec::new();
        let prefix = Key::parse("prefix".to_owned())
            .expect("cannot parse the key string");
        for i in (0..9).rev() {
            let key = prefix
                .push(&format!("{}", i))
                .expect("cannot push the key segment");
            let value_bytes = types::encode(&(i as u64));
            // insert
            storage
                .write(&key, value_bytes.clone())
                .expect("write failed");
            expected.push((key.to_string(), value_bytes));
        }
        storage.commit().expect("commit failed");

        let (iter, gas) = storage.iter_prefix(&prefix);
        assert_eq!(gas, prefix.len() as u64);
        for (k, v, gas) in iter {
            match expected.pop() {
                Some((expected_key, expected_val)) => {
                    assert_eq!(k, expected_key);
                    assert_eq!(v, expected_val);
                    let expected_gas = expected_key.len() + expected_val.len();
                    assert_eq!(gas, expected_gas as u64);
                }
                None => panic!("read a pair though no expected pair"),
            }
        }
    }

    #[test]
    fn test_validity_predicate() {
        let db_path = TempDir::new("anoma_test")
            .expect("Unable to create a temporary DB directory");
        let mut storage = PersistentStorage::new(db_path.path());
        storage
            .begin_block(BlockHash::default(), BlockHeight(100))
            .expect("begin_block failed");

        let addr = storage.address_gen.generate_address("test".as_bytes());
        let key =
            Key::validity_predicate(&addr).expect("cannot create a VP key");

        // not exist
        let (vp, gas) =
            storage.validity_predicate(&addr).expect("VP load failed");
        assert_eq!(vp, None);
        assert_eq!(gas, key.len() as u64);

        // insert
        let vp1 = "vp1".as_bytes().to_vec();
        storage.write(&key, vp1.clone()).expect("write failed");

        // check
        let (vp, gas) =
            storage.validity_predicate(&addr).expect("VP load failed");
        assert_eq!(vp.expect("no VP"), vp1);
        assert_eq!(gas, (key.len() + vp1.len()) as u64);
    }
}

#[cfg(feature = "testing")]
pub mod testing {
    use super::*;

    /// Storage with a mock DB for testing
    pub type TestStorage = Storage<db::mock::MockDB>;

    impl Default for TestStorage {
        fn default() -> Self {
            let tree = MerkleTree::default();
            let subspaces = HashMap::new();
            let block = BlockStorage {
                tree,
                hash: BlockHash::default(),
                height: BlockHeight(0),
                subspaces,
            };
            Self {
                db: db::mock::MockDB::default(),
                chain_id: String::with_capacity(CHAIN_ID_LENGTH),
                block,
                current_height: BlockHeight(0),
                address_gen: EstablishedAddressGen::new(
                    "Test address generator seed",
                ),
            }
        }
    }
}
