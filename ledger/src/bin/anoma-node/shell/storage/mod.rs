//! The storage module handles both the current state in-memory and the stored
//! state in DB.

mod db;
mod types;

pub use self::types::{
    Address, Balance, BasicAddress, BlockHash, BlockHeight, MerkleTree,
    ValidatorAddress,
};
use self::types::{Hash256, CHAIN_ID_LENGTH};
use super::MerkleRoot;
use anoma::bytes::ByteBuf;
use sparse_merkle_tree::{SparseMerkleTree, H256};
use std::{collections::HashMap, ops::Deref, path::PathBuf};

#[derive(Debug, Clone)]
pub enum Error {
    // TODO strong types
    Stringly(String),
    DBError(db::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Storage {
    db_path: PathBuf,
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
}

impl Storage {
    pub fn new(db_path: PathBuf) -> Self {
        let tree = MerkleTree::default();
        let balances = HashMap::new();
        let block = BlockStorage {
            tree,
            hash: BlockHash::default(),
            height: BlockHeight(0),
            balances,
        };
        Self {
            db_path,
            chain_id: String::with_capacity(CHAIN_ID_LENGTH),
            block,
        }
    }

    /// Load the full state at the last committed height, if any. Returns the
    /// Merkle root hash and the height of the committed block.
    pub fn load_last_state(&mut self) -> Result<Option<(MerkleRoot, u64)>> {
        let mut db = db::open(&self.db_path).map_err(Error::DBError)?;
        if let Ok(Some((chain_id, tree, hash, height, balances))) =
            db.read_last_block().map_err(Error::DBError)
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
    pub fn commit(&self) -> Result<()> {
        // TODO DB sub-dir with chain ID?
        let mut db = db::open(&self.db_path).map_err(Error::DBError)?;
        db.write_block(
            &self.block.tree,
            &self.block.hash,
            &self.block.height,
            &self.block.balances,
        )
        .map_err(Error::DBError)
    }

    /// # Storage reads
    pub fn merkle_root(&self) -> &H256 {
        self.block.tree.0.root()
    }

    // TODO this doesn't belong here, temporary for convenience...
    pub fn has_balance_gte(&self, addr: &Address, amount: u64) -> Result<()> {
        match self.block.balances.get(&addr) {
            None => return Err(Error::Stringly("Source not found".to_owned())),
            Some(&Balance(src_balance)) => {
                if src_balance < amount {
                    return Err(Error::Stringly(
                        "Source balance is too low".to_owned(),
                    ));
                };
            }
        }
        Ok(())
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
            .map_err(|err| Error::Stringly(format!("SMT error {}", err)))?;
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
            None => return Err(Error::Stringly("Source not found".to_owned())),
            Some(&Balance(src_balance)) => {
                if src_balance < amount {
                    return Err(Error::Stringly(
                        "Source balance is too low".to_owned(),
                    ));
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
        let mut db = db::open(&self.db_path).map_err(Error::DBError)?;
        db.write_chain_id(&self.chain_id).map_err(Error::DBError)?;
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
