#[cfg(any(test, feature = "testing"))]
pub mod mockdb;
pub mod types;
pub mod write_log;

use std::collections::HashMap;
use std::ops::Deref;

use sparse_merkle_tree::H256;
use thiserror::Error;
use types::MerkleTree;

use crate::ledger::gas::MIN_STORAGE_GAS;
use crate::types::address::EstablishedAddressGen;
use crate::types::{
    Address, BlockHash, BlockHeight, Key, BLOCK_HASH_LENGTH, CHAIN_ID_LENGTH,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Storage<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    pub db: D,
    pub chain_id: String,
    pub block: BlockStorage<H>,
    pub current_height: BlockHeight,
    pub address_gen: EstablishedAddressGen,
}

#[derive(Debug)]
pub struct BlockStorage<H: StorageHasher> {
    pub tree: MerkleTree<H>,
    pub hash: BlockHash,
    pub height: BlockHeight,
    pub subspaces: HashMap<Key, Vec<u8>>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("TEMPORARY error: {error}")]
    Temporary { error: String },
    #[error("Found an unknown key: {key}")]
    UnknownKey { key: String },
    #[error("Key error {0}")]
    KeyError(crate::types::Error),
    #[error("Coding error: {0}")]
    CodingError(types::Error),
    #[error("Merkle tree error: {0}")]
    MerkleTreeError(sparse_merkle_tree::error::Error),
    #[error("Merkle tree error: {0}")]
    DBError(String),
}

pub struct BlockState<H: StorageHasher> {
    pub chain_id: String,
    pub tree: MerkleTree<H>,
    pub hash: BlockHash,
    pub height: BlockHeight,
    pub subspaces: HashMap<Key, Vec<u8>>,
    pub address_gen: EstablishedAddressGen,
}

pub trait DB: std::fmt::Debug {
    /// Flush data on the memory to persistent them
    fn flush(&self) -> Result<()>;

    /// Write a block
    fn write_block<H: StorageHasher>(
        &mut self,
        tree: &MerkleTree<H>,
        hash: &BlockHash,
        height: BlockHeight,
        subspaces: &HashMap<Key, Vec<u8>>,
        address_gen: &EstablishedAddressGen,
    ) -> Result<()>;

    /// Write the chain ID
    #[allow(clippy::ptr_arg)]
    fn write_chain_id(&mut self, chain_id: &String) -> Result<()>;

    /// Read the value with the given height and the key from the DB
    fn read(&self, height: BlockHeight, key: &Key) -> Result<Option<Vec<u8>>>;

    /// Read the last committed block
    fn read_last_block<H: StorageHasher>(
        &mut self,
    ) -> Result<Option<BlockState<H>>>;
}

pub trait DBIter<'iter> {
    type PrefixIter: Iterator<Item = (String, Vec<u8>, u64)>;

    /// Read key value pairs with the given prefix from the DB
    fn iter_prefix(
        &'iter self,
        height: BlockHeight,
        prefix: &Key,
    ) -> Self::PrefixIter;
}

pub struct MerkleRoot(pub Vec<u8>);

impl<D, H> Storage<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Load the full state at the last committed height, if any. Returns the
    /// Merkle root hash and the height of the committed block.
    pub fn load_last_state(&mut self) -> Result<Option<(MerkleRoot, u64)>> {
        if let Some(BlockState {
            chain_id,
            tree,
            hash,
            height,
            subspaces,
            address_gen,
        }) = self.db.read_last_block()?
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
        self.db.write_block(
            &self.block.tree,
            &self.block.hash,
            self.block.height,
            &self.block.subspaces,
            &self.address_gen,
        )?;
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
                .get(&H::hash_key(key))
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

        match self.db.read(self.current_height, key)? {
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
    ) -> (<D as DBIter<'_>>::PrefixIter, u64) {
        (
            self.db.iter_prefix(self.current_height, prefix),
            prefix.len() as _,
        )
    }

    /// Write a value to the specified subspace and returns the gas cost and the
    /// size difference
    pub fn write(&mut self, key: &Key, value: Vec<u8>) -> Result<(u64, i64)> {
        self.update_tree(H::hash_key(key), H::hash_value(&value))?;

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
            self.update_tree(H::hash_key(key), H256::zero())?;

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
        self.db.write_chain_id(&self.chain_id)?;
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

pub trait StorageHasher: sparse_merkle_tree::traits::Hasher + Default {
    fn hash_key(key: &Key) -> H256;
    fn hash_value(value: impl AsRef<[u8]>) -> H256;
}

#[cfg(feature = "testing")]
pub mod testing {
    use std::convert::TryInto;

    use sha2::{Digest, Sha256};
    use sparse_merkle_tree::H256;

    use super::mockdb::MockDB;
    use super::*;

    pub struct Sha256Hasher(Sha256);

    impl Default for Sha256Hasher {
        fn default() -> Self {
            Self(Sha256::default())
        }
    }

    impl sparse_merkle_tree::traits::Hasher for Sha256Hasher {
        fn write_h256(&mut self, h: &H256) {
            self.0.update(h.as_slice());
        }

        fn finish(self) -> H256 {
            let hash = self.0.finalize();
            let bytes: [u8; 32] = hash.as_slice().try_into().expect(
                "Sha256 output conversion to fixed array shouldn't fail",
            );
            bytes.into()
        }
    }

    impl StorageHasher for Sha256Hasher {
        fn hash_key(key: &Key) -> H256 {
            let mut hasher = Sha256::new();
            hasher.update(&types::encode(key));
            let hash = hasher.finalize();
            let bytes: [u8; 32] = hash.as_slice().try_into().expect(
                "Sha256 output conversion to fixed array shouldn't fail",
            );
            bytes.into()
        }

        fn hash_value(value: impl AsRef<[u8]>) -> H256 {
            let mut hasher = Sha256::new();
            hasher.update(value.as_ref());
            let hash = hasher.finalize();
            let bytes: [u8; 32] = hash.as_slice().try_into().expect(
                "Sha256 output conversion to fixed array shouldn't fail",
            );
            bytes.into()
        }
    }

    /// Storage with a mock DB for testing
    pub type TestStorage = Storage<MockDB, Sha256Hasher>;

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
                db: MockDB::default(),
                chain_id: "Testing-chain".to_string(),
                block,
                current_height: BlockHeight(0),
                address_gen: EstablishedAddressGen::new(
                    "Test address generator seed",
                ),
            }
        }
    }
}
