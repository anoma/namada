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
    Address, Balance, BasicAddress, BlockHash, BlockHeight, MerkleTree,
    ValidatorAddress,
};
use self::types::{Hash256, CHAIN_ID_LENGTH};
use super::MerkleRoot;

#[derive(Error, Debug)]
pub enum Error {
    #[error("TEMPORARY error: {error}")]
    Temporary { error: String },
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
    balances: HashMap<Address, Balance>,
    vps: HashMap<Address, Vec<u8>>,
}

impl Storage {
    pub fn new(db_path: PathBuf) -> Self {
        let tree = MerkleTree::default();
        let balances = HashMap::new();
        let vps = HashMap::new();
        let block = BlockStorage {
            tree,
            hash: BlockHash::default(),
            height: BlockHeight(0),
            balances,
            vps,
        };
        Self {
            // TODO: Error handling
            db: db::open(&db_path).unwrap(),
            chain_id: String::with_capacity(CHAIN_ID_LENGTH),
            block,
        }
    }

    /// Load the full state at the last committed height, if any. Returns the
    /// Merkle root hash and the height of the committed block.
    pub fn load_last_state(&mut self) -> Result<Option<(MerkleRoot, u64)>> {
        if let Some((chain_id, tree, hash, height, balances)) =
            self.db.read_last_block().map_err(Error::DBError)?
        {
            self.chain_id = chain_id;
            self.block.tree = tree;
            self.block.hash = hash;
            self.block.height = height;
            self.block.balances = balances;
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
                &self.block.height,
                &self.block.balances,
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

    pub fn update_balance(
        &mut self,
        addr: &Address,
        balance: Balance,
    ) -> Result<()> {
        let key = addr.hash256();
        let value = balance.hash256();
        self.update_tree(key, value)?;
        self.block.balances.insert(addr.clone(), balance);
        Ok(())
    }

    // TODO this doesn't belong here, temporary for convenience...
    pub fn transfer(
        &mut self,
        src: &Address,
        dest: &Address,
        amount: u64,
    ) -> Result<()> {
        match self.block.balances.get(&src) {
            None => {
                return Err(Error::Temporary {
                    error: format!("Source balance not found {:?}", src),
                });
            }
            Some(&Balance(src_balance)) => {
                if src_balance < amount {
                    return Err(Error::Temporary {
                        error: format!("Source balance is too low {:?}", src),
                    });
                };
                self.update_balance(src, Balance::new(src_balance - amount))?;
                match self.block.balances.get(&dest) {
                    None => self.update_balance(dest, Balance::new(amount))?,
                    Some(&Balance(dest_balance)) => self.update_balance(
                        dest,
                        Balance::new(dest_balance + amount),
                    )?,
                }
                Ok(())
            }
        }
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
        match self.block.vps.get(addr) {
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
