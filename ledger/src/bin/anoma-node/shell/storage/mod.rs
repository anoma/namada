//! The storage module handles both the current state in-memory and the stored
//! state in DB.

mod db;
mod types;

use std::collections::HashMap;
use std::ops::Deref;
use std::path::PathBuf;

use anoma::bytes::ByteBuf;
use sparse_merkle_tree::{SparseMerkleTree, H256};
use thiserror::Error;

pub use self::types::{
    Address, BasicAddress, BlockHash, BlockHeight, Key, KeySeg, MerkleTree,
    ValidatorAddress, Value,
};
use self::types::{Hash256, CHAIN_ID_LENGTH};
use super::MerkleRoot;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Key error {0}")]
    KeyError(types::Error),
    #[error("Database error: {0}")]
    DBError(db::Error),
    #[error("Merkle tree error: {0}")]
    MerkleTreeError(sparse_merkle_tree::error::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

static VP_WASM: &'static [u8] =
    include_bytes!("../../../../../../vp_template/vp.wasm");

#[derive(Debug)]
pub struct Storage {
    db: db::DB,
    chain_id: String,
    // TODO Because the transaction may modify and state, we'll probably need
    // to split into read-only last block state and mutable current block state
    // for write-only. When the block is committed, the former will be updated
    // to the state of the latter
    block: BlockStorage,
}

#[derive(Debug)]
pub struct BlockStorage {
    tree: MerkleTree,
    hash: BlockHash,
    height: BlockHeight,
    subspaces: HashMap<Key, Vec<u8>>,
}

impl Storage {
    pub fn new(db_path: &PathBuf) -> Self {
        let tree = MerkleTree::default();
        let subspaces = HashMap::new();
        let block = BlockStorage {
            tree,
            hash: BlockHash::default(),
            height: BlockHeight(0),
            subspaces,
        };
        Self {
            // TODO: Error handling
            db: db::open(db_path).unwrap(),
            chain_id: String::with_capacity(CHAIN_ID_LENGTH),
            block,
        }
    }

    /// Load the full state at the last committed height, if any. Returns the
    /// Merkle root hash and the height of the committed block.
    pub fn load_last_state(&mut self) -> Result<Option<(MerkleRoot, u64)>> {
        if let Some((chain_id, tree, hash, height, subspaces)) =
            self.db.read_last_block().map_err(Error::DBError)?
        {
            self.chain_id = chain_id;
            self.block.tree = tree;
            self.block.hash = hash;
            self.block.height = height;
            self.block.subspaces = subspaces;
            log::debug!("Loaded storage from DB: {:#?}", self);
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
            )
            .map_err(|e| Error::DBError(e).into())
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

    pub fn has_key(&self, key: &Key) -> Result<bool> {
        Ok(!self
            .block
            .tree
            .0
            .get(&key.hash256())
            .map_err(Error::MerkleTreeError)?
            .is_zero())
    }

    /// Returns a value from the specified subspace and the gas cost
    pub fn read(&self, key: &Key) -> Result<(Option<Vec<u8>>, u64)> {
        if !self.has_key(key)? {
            return Ok((None, 0));
        }

        if let Some(v) = self.block.subspaces.get(key) {
            return Ok((Some(v.to_vec()), v.len() as u64));
        }

        match self
            .db
            .read(self.block.height, key)
            .map_err(Error::DBError)?
        {
            Some(v) => {
                let len = v.len() as u64;
                Ok((Some(v), len))
            }
            None => Ok((None, 0)),
        }
    }

    /// Write a value to the specified subspace and returns the gas cost and the
    /// size difference
    pub fn write(&mut self, key: &Key, value: Vec<u8>) -> Result<(u64, i64)> {
        self.update_tree(key.hash256(), value.hash256())?;

        let len = value.len();
        let size_diff = match self.block.subspaces.insert(key.clone(), value) {
            Some(old) => len as i64 - old.len() as i64,
            None => 0,
        };
        Ok((len as u64, size_diff))
    }

    /// Delete the specified subspace and returns the gas cost and the size
    /// difference
    pub fn delete(&mut self, key: &Key) -> Result<(u64, i64)> {
        let mut size_diff = 0;
        if self.has_key(key)? {
            // update the merkle tree with a zero as a tombstone
            self.update_tree(key.hash256(), H256::zero())?;

            size_diff -= match self.block.subspaces.remove(key) {
                Some(old) => old.len() as i64,
                None => 0,
            };
        }
        Ok((-size_diff as u64, size_diff))
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

    /// Get a validity predicate for the given account address
    pub fn validity_predicate(&self, addr: &Address) -> Result<Vec<u8>> {
        let key = Key::from(addr.to_db_key())
            .push(&"vp".to_owned())
            .map_err(Error::KeyError)?;
        match self.read(&key)?.0 {
            Some(vp) => Ok(vp.clone()),
            // TODO: this temporarily loads default VP template if none found
            None => Ok(VP_WASM.to_vec()),
        }
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        MerkleTree(SparseMerkleTree::default())
    }
}

impl core::fmt::Debug for MerkleTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let root_hash = format!("{}", ByteBuf(self.0.root().as_slice()));
        f.debug_struct("MerkleTree")
            .field("root_hash", &root_hash)
            .finish()
    }
}
