//! Ledger's state storage with key-value backed store and a merkle tree

#[cfg(any(test, feature = "testing"))]
pub mod mockdb;
pub mod types;
pub mod write_log;

use core::fmt::Debug;
use std::collections::HashMap;
use std::fmt::Display;

use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::{SparseMerkleTree, H256};
use thiserror::Error;
use types::MerkleTree;

use crate::bytes::ByteBuf;
use crate::ledger::gas::MIN_STORAGE_GAS;
use crate::types::address::{Address, EstablishedAddressGen};
use crate::types::storage::{
    BlockHash, BlockHeight, Epoch, Key, BLOCK_HASH_LENGTH, CHAIN_ID_LENGTH,
};
use crate::types::time::DateTimeUtc;

/// A result of a function that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// The storage data
#[derive(Debug)]
pub struct Storage<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// The database for the storage
    pub db: D,
    /// The ID of the chain
    pub chain_id: String,
    /// The storage for the last committed block
    pub block: BlockStorage<H>,
    /// The height of the current block
    pub current_height: BlockHeight,
    /// The epoch of the current block
    pub current_epoch: Epoch,
    /// Block height at which the current epoch started
    pub epoch_start_height: BlockHeight,
    /// Block time at which the current epoch started
    pub epoch_start_time: DateTimeUtc,
    /// The current established address generator
    pub address_gen: EstablishedAddressGen,
}

/// The block storage data
#[derive(Debug)]
pub struct BlockStorage<H: StorageHasher> {
    /// Merkle tree of all the other data in block storage
    pub tree: MerkleTree<H>,
    /// Hash of the block
    pub hash: BlockHash,
    /// Height of the block (i.e. the level)
    pub height: BlockHeight,
    /// Epoch of the block
    pub epoch: Epoch,
    /// Accounts' subspaces storage for arbitrary key-values
    pub subspaces: HashMap<Key, Vec<u8>>,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("TEMPORARY error: {error}")]
    Temporary { error: String },
    #[error("Found an unknown key: {key}")]
    UnknownKey { key: String },
    #[error("Storage key error {0}")]
    KeyError(crate::types::storage::Error),
    #[error("Coding error: {0}")]
    CodingError(types::Error),
    #[error("Merkle tree error: {0}")]
    MerkleTreeError(sparse_merkle_tree::error::Error),
    #[error("Merkle tree error: {0}")]
    DBError(String),
}

/// The block's state as stored in the database.
pub struct BlockState {
    /// Merkle tree root
    pub root: H256,
    /// Merkle tree store
    pub store: DefaultStore<H256>,
    /// Hash of the block
    pub hash: BlockHash,
    /// Height of the block
    pub height: BlockHeight,
    /// Epoch of the block
    pub epoch: Epoch,
    /// Block height at which the current epoch started
    pub epoch_start_height: BlockHeight,
    /// Block time at which the current epoch started
    pub epoch_start_time: DateTimeUtc,
    /// Accounts' subspaces storage for arbitrary key-values
    pub subspaces: HashMap<Key, Vec<u8>>,
    /// Established address generator
    pub address_gen: EstablishedAddressGen,
}

/// A database backend.
pub trait DB: std::fmt::Debug {
    /// Flush data on the memory to persistent them
    fn flush(&self) -> Result<()>;

    /// Write a block
    fn write_block(&mut self, state: BlockState) -> Result<()>;

    /// Read the value with the given height and the key from the DB
    fn read(&self, height: BlockHeight, key: &Key) -> Result<Option<Vec<u8>>>;

    /// Read the last committed block
    fn read_last_block(&mut self) -> Result<Option<BlockState>>;
}

/// A database prefix iterator.
pub trait DBIter<'iter> {
    /// The concrete type of the iterator
    type PrefixIter: Debug + Iterator<Item = (String, Vec<u8>, u64)>;

    /// Read key value pairs with the given prefix from the DB
    fn iter_prefix(
        &'iter self,
        height: BlockHeight,
        prefix: &Key,
    ) -> Self::PrefixIter;
}

/// The root hash of the merkle tree as bytes
pub struct MerkleRoot(pub Vec<u8>);

impl Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", ByteBuf(&self.0))
    }
}

impl<D, H> Storage<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Load the full state at the last committed height, if any. Returns the
    /// Merkle root hash and the height of the committed block.
    pub fn load_last_state(&mut self) -> Result<()> {
        if let Some(BlockState {
            root,
            store,
            hash,
            height,
            epoch,
            epoch_start_height,
            epoch_start_time,
            subspaces,
            address_gen,
        }) = self.db.read_last_block()?
        {
            self.block.tree = MerkleTree(SparseMerkleTree::new(root, store));
            self.block.hash = hash;
            self.block.height = height;
            self.block.epoch = epoch;
            self.block.subspaces = subspaces;
            self.current_height = height;
            self.current_epoch = epoch;
            self.epoch_start_height = epoch_start_height;
            self.epoch_start_time = epoch_start_time;
            self.address_gen = address_gen;
            tracing::debug!("Loaded storage from DB");
        } else {
            tracing::info!("No state could be found");
        }
        Ok(())
    }

    /// Returns the Merkle root hash and the height of the committed block. If
    /// no block exists, returns None.
    pub fn get_state(&self) -> Option<(MerkleRoot, u64)> {
        if self.block.height.0 != 0 {
            Some((
                MerkleRoot(self.block.tree.0.root().as_slice().to_vec()),
                self.block.height.0,
            ))
        } else {
            None
        }
    }

    /// Persist the current block's state to the database
    pub fn commit(&mut self) -> Result<()> {
        let state = BlockState {
            root: *self.block.tree.0.root(),
            store: self.block.tree.0.store().clone(),
            hash: self.block.hash.clone(),
            height: self.block.height,
            epoch: self.block.epoch,
            epoch_start_height: self.epoch_start_height,
            epoch_start_time: self.epoch_start_time.clone(),
            subspaces: self.block.subspaces.clone(),
            address_gen: self.address_gen.clone(),
        };
        self.db.write_block(state)?;
        self.current_height = self.block.height;
        Ok(())
    }

    /// Find the root hash of the merkle tree
    pub fn merkle_root(&self) -> MerkleRoot {
        MerkleRoot(self.block.tree.0.root().as_slice().to_vec())
    }

    /// Update the merkle tree with a storage key-value.
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

    /// Check if the given key is present in storage. Returns the result and the
    /// gas cost.
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
        tracing::debug!("storage read key {}", key,);
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
        tracing::debug!("storage write key {}", key,);
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

    /// Set the chain ID.
    /// Chain ID is not in the Merkle tree as it's tracked by Tendermint in the
    /// block header. Hence, we don't update the tree when this is set.
    pub fn set_chain_id(&mut self, chain_id: &str) -> Result<()> {
        self.chain_id = chain_id.to_owned();
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
        let key = Key::validity_predicate(addr);
        self.read(&key)
    }

    #[allow(dead_code)]
    /// Check if the given address exists on chain and return the gas cost.
    pub fn exists(&self, addr: &Address) -> Result<(bool, u64)> {
        let key = Key::validity_predicate(addr);
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

    /// Get the current (yet to be committed) block epoch
    pub fn get_block_epoch(&self) -> (Epoch, u64) {
        (self.block.epoch, MIN_STORAGE_GAS)
    }
}

/// The storage hasher used for the merkle tree.
pub trait StorageHasher: sparse_merkle_tree::traits::Hasher + Default {
    /// Hash a storage key
    fn hash_key(key: &Key) -> H256;
    /// Hash a storage value
    fn hash_value(value: impl AsRef<[u8]>) -> H256;
}

/// Helpers for testing components that depend on storage
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::convert::TryInto;

    use sha2::{Digest, Sha256};
    use sparse_merkle_tree::H256;

    use super::mockdb::MockDB;
    use super::*;

    /// The storage hasher used for the merkle tree.
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
            let chain_id = "Testing-chain-000000".to_string();
            assert_eq!(chain_id.len(), CHAIN_ID_LENGTH);
            let tree = MerkleTree::default();
            let subspaces = HashMap::new();
            let block = BlockStorage {
                tree,
                hash: BlockHash::default(),
                height: BlockHeight::default(),
                epoch: Epoch::default(),
                subspaces,
            };
            Self {
                db: MockDB::default(),
                chain_id,
                block,
                current_height: BlockHeight::default(),
                current_epoch: Epoch::default(),
                epoch_start_height: BlockHeight::default(),
                epoch_start_time: DateTimeUtc::now(),
                address_gen: EstablishedAddressGen::new(
                    "Test address generator seed",
                ),
            }
        }
    }
}
