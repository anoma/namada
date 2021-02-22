//! The storage module handles both the current state in-memory and the stored
//! state in DB.

mod db;
mod types;

use anoma::bytes::ByteBuf;
use rocksdb::WriteBatch;
use sparse_merkle_tree::{default_store::DefaultStore, SparseMerkleTree, H256};
use std::{collections::HashMap, ops::Deref, path::PathBuf};
use types::{BlockHeight, KeySeg, Value};

pub use self::types::{
    Address, Balance, BasicAddress, BlockHash, MerkleTree, ValidatorAddress,
};
use self::types::{Hash256, CHAIN_ID_LENGTH};

use super::MerkleRoot;

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
        // TODO the rocksdb impl should be contained in the db module
        let db = db::open(&self.db_path).map_err(Error::DBError)?;
        match db
            .get("height")
            .map_err(|e| Error::DBError(db::Error::RocksDBError(e)))?
        {
            Some(bytes) => {
                // TODO if there's an issue decoding this height, should we try
                // on a pred?
                let height = BlockHeight::decode(bytes);
                let prefix = height.to_key_seg();
                // Merkle tree
                {
                    let tree_prefix = format!("{}/tree", prefix);
                    // Merkle root hash
                    {
                        let key = format!("{}/root", tree_prefix);
                        match db.get(key).map_err(|e| {
                            Error::DBError(db::Error::RocksDBError(e))
                        })? {
                            Some(raw_root) => {
                                let root = H256::decode(raw_root);

                                // Tree's store
                                {
                                    let key = format!("{}/store", tree_prefix);
                                    let bytes = db
                                        .get(key)
                                        .map_err(|e| {
                                            Error::DBError(
                                                db::Error::RocksDBError(e),
                                            )
                                        })?
                                        .unwrap();
                                    let store =
                                        DefaultStore::<H256>::decode(bytes);
                                    self.block.tree = MerkleTree(
                                        SparseMerkleTree::new(root, store),
                                    )
                                }
                                // Block hash
                                {
                                    let key = format!("{}/hash", prefix);
                                    let bytes = db
                                        .get(key)
                                        .map_err(|e| {
                                            Error::DBError(
                                                db::Error::RocksDBError(e),
                                            )
                                        })?
                                        .unwrap();
                                    let hash = BlockHash::decode(bytes);
                                    self.block.hash = hash;
                                }
                                // Balances
                                {
                                    let prefix = format!("{}/balance/", prefix);
                                    for (key, bytes) in
                                        db.prefix_iterator(&prefix)
                                    {
                                        // decode the key and strip the prefix
                                        let path =
                                            &String::from_utf8((*key).to_vec())
                                                .map_err(|e| {
                                                    Error::Stringly(format!(
                                                "error decoding an address: {}",
                                                e
                                            ))
                                                })?;
                                        match path.strip_prefix(&prefix) {
                                            Some(segment) => {
                                                let addr =
                                                    Address::from_key_seg(
                                                        &segment.to_owned(),
                                                    )
                                                    .map_err(|e| {
                                                        Error::Stringly(
                                                            format!(
                                                "error decoding an address: {}",
                                                e
                                            ),
                                                        )
                                                    })?;
                                                let balance = Balance::decode(
                                                    bytes.to_vec(),
                                                );
                                                self.block
                                                    .balances
                                                    .insert(addr, balance);
                                            }
                                            None => {
                                                // TODO the prefix_iterator is
                                                // going into non-matching
                                                // prefixes
                                                log::debug!("Cannot find prefix \"{}\" in \"{}\"", prefix, path);
                                            }
                                        }
                                    }
                                }

                                self.block.height = height;
                                log::debug!(
                                    "Loaded storage from DB: {:#?}",
                                    self
                                );
                                Ok(Some((
                                    MerkleRoot(
                                        root.as_slice().deref().to_vec(),
                                    ),
                                    self.block.height.0,
                                )))
                            }
                            None => Ok(None),
                        }
                    }
                }
            }
            None => Ok(None),
        }
    }

    /// Persist the current block's state to the database
    pub fn commit(&self) -> Result<()> {
        // TODO DB sub-dir with chain ID?
        let db = db::open(&self.db_path).map_err(Error::DBError)?;
        let mut batch = WriteBatch::default();
        let prefix = self.block.height.to_key_seg();
        // Merkle tree
        {
            // TODO add and use `to_key_seg` for these
            let prefix = format!("{}/tree", prefix);
            // Merkle root hash
            {
                let key = format!("{}/root", prefix);
                let value = self.merkle_root();
                batch.put(key, value.as_slice());
            }
            // Tree's store
            {
                let key = format!("{}/store", prefix);
                let value = self.block.tree.0.store();
                batch.put(key, value.encode());
            }
        }
        // Block hash
        {
            let key = format!("{}/hash", prefix);
            let value = &self.block.hash;
            batch.put(key, value.encode());
        }
        // Balances
        {
            self.block.balances.iter().for_each(|(addr, balance)| {
                let key = format!("{}/balance/{}", prefix, addr.to_key_seg());
                batch.put(key, balance.encode());
            });
        }
        db.write(batch)
            .map_err(|e| Error::DBError(db::Error::RocksDBError(e)))?;
        // Write height after everything else is written
        // TODO for async writes, we need to take care that all previous heights
        // are known when updating this
        db.put("height", self.block.height.encode())
            .map_err(|e| Error::DBError(db::Error::RocksDBError(e)))?;
        db.flush()
            .map_err(|e| Error::DBError(db::Error::RocksDBError(e)))?;
        Ok(())
    }

    /// # Storage reads
    pub fn merkle_root(&self) -> &H256 {
        self.block.tree.0.root()
    }

    // TODO this doesn't belong here, but just for convenience...
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

    // TODO this doesn't belong here, but just for convenience...
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
        self.chain_id = chain_id.to_owned();
        Ok(())
    }

    /// Block data is in the Merkle tree as it's tracked by Tendermint in the
    /// block header. Hence, we don't update the tree when this is set.
    pub fn begin_block(&mut self, hash: BlockHash, height: u64) -> Result<()> {
        self.block.hash = hash;
        self.block.height = BlockHeight(height);
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
