//! The storage module handles both the current state in-memory and the stored
//! state in DB.

mod db;

use anoma::bytes::ByteBuf;
use blake2b_rs::{Blake2b, Blake2bBuilder};
use rocksdb::WriteBatch;
use sparse_merkle_tree::{
    blake2b::Blake2bHasher, default_store::DefaultStore, SparseMerkleTree, H256,
};
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fmt::write,
    hash::Hash,
    path::{Path, PathBuf},
};

use super::MerkleRoot;

// TODO adjust once chain ID scheme is chosen
const CHAIN_ID_LENGTH: usize = 20;
const BLOCK_HASH_LENGTH: usize = 32;

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
    height: u64,
    balances: HashMap<Address, Balance>,
}

pub struct BlockHash([u8; 32]);

struct MerkleTree(SparseMerkleTree<Blake2bHasher, H256, DefaultStore<H256>>);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Address {
    Validator(ValidatorAddress),
    Basic(BasicAddress),
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BasicAddress(String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ValidatorAddress(String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Balance(u64);

impl Storage {
    pub fn new(db_path: PathBuf) -> Self {
        let tree = MerkleTree::default();
        let balances = HashMap::new();
        let block = BlockStorage {
            tree,
            hash: BlockHash::default(),
            height: 0,
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
            Some(raw_height) => {
                let height =
                    u64::from_le_bytes(raw_height.try_into().map_err(|e| {
                        Error::Stringly(format!(
                            "height encoding error {:?}",
                            e
                        ))
                    })?);
                let prefix = format!("b/{}", height);

                // Merkle tree
                {
                    let prefix = format!("{}/tree", prefix);
                    // Merkle root hash
                    {
                        let key = format!("{}/root", prefix);
                        match db.get(key).map_err(|e| {
                            Error::DBError(db::Error::RocksDBError(e))
                        })? {
                            Some(raw_root) => {
                                let root = MerkleRoot(raw_root);
                                // TODO set the current state from these
                                self.block.height = height;
                                Ok(Some((root, height)))
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
        // TODO the rocksdb impl should be contained in the db module
        // TODO DB sub-dir with chain ID?
        let db = db::open(&self.db_path).map_err(Error::DBError)?;
        // TODO pick an encoding lib
        // TODO store paths and data:
        // - "height": the last committed height
        //   - write after everything else is written?
        //   - for async writes, we need to take care that all previous heights
        //     are known when updating this
        // - "b/h" for each block at height "h":
        //   - "tree": merkle tree
        //     - "root": root hash
        //     - "branches/H256": stored branches
        //     - "leaves/H256": stored leaves
        //   - "hash": hash
        //   - "balance/address": balance for each account address
        let mut batch = WriteBatch::default();
        let prefix = format!("b/{}", self.block.height);
        // Merkle tree
        {
            let prefix = format!("{}/tree", prefix);
            // Merkle root hash
            {
                let key = format!("{}/root", prefix);
                let value = self.merkle_root();
                batch.put(key, value.as_slice());
            }
        }
        db.write(batch)
            .map_err(|e| Error::DBError(db::Error::RocksDBError(e)))?;
        db.put("height", self.block.height.to_le_bytes())
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
        self.block.height = height;
        Ok(())
    }
}

impl Default for BlockHash {
    fn default() -> Self {
        Self([0; 32])
    }
}

impl TryFrom<&[u8]> for BlockHash {
    type Error = self::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != BLOCK_HASH_LENGTH {
            return Err(Error::Stringly(format!(
                "Unexpected block hash length {}, expected {}",
                value.len(),
                BLOCK_HASH_LENGTH
            )));
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(value);
        Ok(BlockHash(hash))
    }
}

impl core::fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = format!("{}", ByteBuf(&self.0));
        f.debug_tuple("BlockHash").field(&hash).finish()
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

// TODO make derive macro for Hash256 https://doc.rust-lang.org/book/ch19-06-macros.html#how-to-write-a-custom-derive-macro
trait Hash256 {
    fn hash256(&self) -> H256;
}

impl Hash256 for Address {
    fn hash256(&self) -> H256 {
        match self {
            Address::Basic(addr) => addr.hash256(),
            Address::Validator(addr) => addr.hash256(),
        }
    }
}

impl BasicAddress {
    pub fn new_address(addr: String) -> Address {
        Address::Basic(Self(addr))
    }
}
impl Hash256 for BasicAddress {
    fn hash256(&self) -> H256 {
        self.0.hash256()
    }
}

impl ValidatorAddress {
    pub fn new_address(addr: String) -> Address {
        Address::Validator(Self(addr))
    }
}
impl Hash256 for ValidatorAddress {
    fn hash256(&self) -> H256 {
        self.0.hash256()
    }
}

impl Balance {
    pub fn new(balance: u64) -> Self {
        Self(balance)
    }
}
impl Hash256 for Balance {
    fn hash256(&self) -> H256 {
        if self.0 == 0 {
            return H256::zero();
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&self.0.to_le_bytes());
        hasher.finalize(&mut buf);
        buf.into()
    }
}

impl Hash256 for &str {
    fn hash256(&self) -> H256 {
        if self.is_empty() {
            return H256::zero();
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(self.as_bytes());
        hasher.finalize(&mut buf);
        buf.into()
    }
}

impl Hash256 for String {
    fn hash256(&self) -> H256 {
        if self.is_empty() {
            return H256::zero();
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(self.as_bytes());
        hasher.finalize(&mut buf);
        buf.into()
    }
}

impl Hash256 for [u8; 32] {
    fn hash256(&self) -> H256 {
        if self.is_empty() {
            return H256::zero();
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(self);
        hasher.finalize(&mut buf);
        buf.into()
    }
}

impl Hash256 for u64 {
    fn hash256(&self) -> H256 {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&self.to_le_bytes());
        hasher.finalize(&mut buf);
        buf.into()
    }
}

fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"anoma storage").build()
}
