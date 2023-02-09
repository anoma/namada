//! Ledger's state storage with key-value backed store and a merkle tree

pub mod ics23_specs;
mod masp_conversions;
pub mod merkle_tree;
#[cfg(any(test, feature = "testing"))]
pub mod mockdb;
pub mod traits;
pub mod types;
mod wl_storage;
pub mod write_log;

use core::fmt::Debug;

use merkle_tree::StorageBytes;
pub use merkle_tree::{
    MembershipProof, MerkleTree, MerkleTreeStoresRead, MerkleTreeStoresWrite,
    StoreType,
};
use thiserror::Error;
pub use traits::{Sha256Hasher, StorageHasher};
pub use wl_storage::{
    iter_prefix_post, iter_prefix_pre, PrefixIter, WlStorage,
};

#[cfg(feature = "wasm-runtime")]
pub use self::masp_conversions::update_allowed_conversions;
pub use self::masp_conversions::{encode_asset_type, ConversionState};
use crate::ledger::gas::MIN_STORAGE_GAS;
use crate::ledger::parameters::{self, EpochDuration, Parameters};
use crate::ledger::storage::merkle_tree::{
    Error as MerkleTreeError, MerkleRoot,
};
#[cfg(any(feature = "tendermint", feature = "tendermint-abcipp"))]
use crate::tendermint::merkle::proof::Proof;
use crate::types::address::{
    masp, Address, EstablishedAddressGen, InternalAddress,
};
use crate::types::chain::{ChainId, CHAIN_ID_LENGTH};
// TODO
#[cfg(feature = "ferveo-tpke")]
use crate::types::internal::TxQueue;
use crate::types::storage::{
    BlockHash, BlockHeight, BlockResults, Epoch, Epochs, Header, Key, KeySeg,
    TxIndex, BLOCK_HASH_LENGTH,
};
use crate::types::time::DateTimeUtc;
use crate::types::token;

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
    pub chain_id: ChainId,
    /// The address of the native token - this is not stored in DB, but read
    /// from genesis
    pub native_token: Address,
    /// Block storage data
    pub block: BlockStorage<H>,
    /// During `FinalizeBlock`, this is the header of the block that is
    /// going to be committed. After a block is committed, this is reset to
    /// `None` until the next `FinalizeBlock` phase is reached.
    pub header: Option<Header>,
    /// The height of the most recently committed block, or `BlockHeight(0)` if
    /// no block has been committed for this chain yet.
    pub last_height: BlockHeight,
    /// The epoch of the most recently committed block. If it is `Epoch(0)`,
    /// then no block may have been committed for this chain yet.
    pub last_epoch: Epoch,
    /// Minimum block height at which the next epoch may start
    pub next_epoch_min_start_height: BlockHeight,
    /// Minimum block time at which the next epoch may start
    pub next_epoch_min_start_time: DateTimeUtc,
    /// The current established address generator
    pub address_gen: EstablishedAddressGen,
    /// Epoch update info
    pub epoch_update_tracker: (bool, u32),
    /// The shielded transaction index
    pub tx_index: TxIndex,
    /// The currently saved conversion state
    pub conversion_state: ConversionState,
    /// Wrapper txs to be decrypted in the next block proposal
    #[cfg(feature = "ferveo-tpke")]
    pub tx_queue: TxQueue,
}

/// The block storage data
#[derive(Debug)]
pub struct BlockStorage<H: StorageHasher> {
    /// Merkle tree of all the other data in block storage
    pub tree: MerkleTree<H>,
    /// During `FinalizeBlock`, this is updated to be the hash of the block
    /// that is going to be committed. If it is `BlockHash::default()`,
    /// then no `FinalizeBlock` stage has been reached yet.
    pub hash: BlockHash,
    /// From the start of `FinalizeBlock` until the end of `Commit`, this is
    /// height of the block that is going to be committed. Otherwise, it is the
    /// height of the most recently committed block, or `BlockHeight(0)` if no
    /// block has been committed yet.
    pub height: BlockHeight,
    /// From the start of `FinalizeBlock` until the end of `Commit`, this is
    /// height of the block that is going to be committed. Otherwise it is the
    /// epoch of the most recently committed block, or `Epoch(0)` if no block
    /// has been committed yet.
    pub epoch: Epoch,
    /// Results of applying transactions
    pub results: BlockResults,
    /// Predecessor block epochs
    pub pred_epochs: Epochs,
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
    MerkleTreeError(MerkleTreeError),
    #[error("DB error: {0}")]
    DBError(String),
    #[error("Borsh (de)-serialization error: {0}")]
    BorshCodingError(std::io::Error),
    #[error("Merkle tree at the height {height} is not stored")]
    NoMerkleTree { height: BlockHeight },
}

/// The block's state as stored in the database.
pub struct BlockStateRead {
    /// Merkle tree stores
    pub merkle_tree_stores: MerkleTreeStoresRead,
    /// Hash of the block
    pub hash: BlockHash,
    /// Height of the block
    pub height: BlockHeight,
    /// Epoch of the block
    pub epoch: Epoch,
    /// Predecessor block epochs
    pub pred_epochs: Epochs,
    /// Minimum block height at which the next epoch may start
    pub next_epoch_min_start_height: BlockHeight,
    /// Minimum block time at which the next epoch may start
    pub next_epoch_min_start_time: DateTimeUtc,
    /// Established address generator
    pub address_gen: EstablishedAddressGen,
    /// Results of applying transactions
    pub results: BlockResults,
    /// Wrapper txs to be decrypted in the next block proposal
    #[cfg(feature = "ferveo-tpke")]
    pub tx_queue: TxQueue,
}

/// The block's state to write into the database.
pub struct BlockStateWrite<'a> {
    /// Merkle tree stores
    pub merkle_tree_stores: MerkleTreeStoresWrite<'a>,
    /// Header of the block
    pub header: Option<&'a Header>,
    /// Hash of the block
    pub hash: &'a BlockHash,
    /// Height of the block
    pub height: BlockHeight,
    /// Epoch of the block
    pub epoch: Epoch,
    /// Predecessor block epochs
    pub pred_epochs: &'a Epochs,
    /// Minimum block height at which the next epoch may start
    pub next_epoch_min_start_height: BlockHeight,
    /// Minimum block time at which the next epoch may start
    pub next_epoch_min_start_time: DateTimeUtc,
    /// Established address generator
    pub address_gen: &'a EstablishedAddressGen,
    /// Results of applying transactions
    pub results: &'a BlockResults,
    /// Wrapper txs to be decrypted in the next block proposal
    #[cfg(feature = "ferveo-tpke")]
    pub tx_queue: &'a TxQueue,
}

/// A database backend.
pub trait DB: std::fmt::Debug {
    /// A DB's cache
    type Cache;
    /// A handle for batch writes
    type WriteBatch: DBWriteBatch;

    /// Open the database from provided path
    fn open(
        db_path: impl AsRef<std::path::Path>,
        cache: Option<&Self::Cache>,
    ) -> Self;

    /// Flush data on the memory to persistent them
    fn flush(&self, wait: bool) -> Result<()>;

    /// Read the last committed block's metadata
    fn read_last_block(&mut self) -> Result<Option<BlockStateRead>>;

    /// Write block's metadata
    fn write_block(&mut self, state: BlockStateWrite) -> Result<()>;

    /// Read the block header with the given height from the DB
    fn read_block_header(&self, height: BlockHeight) -> Result<Option<Header>>;

    /// Read the merkle tree stores with the given height
    fn read_merkle_tree_stores(
        &self,
        height: BlockHeight,
    ) -> Result<Option<MerkleTreeStoresRead>>;

    /// Read the latest value for account subspace key from the DB
    fn read_subspace_val(&self, key: &Key) -> Result<Option<Vec<u8>>>;

    /// Read the value for account subspace key at the given height from the DB.
    /// In our `PersistentStorage` (rocksdb), to find a value from arbitrary
    /// height requires looking for diffs from the given `height`, possibly
    /// up to the `last_height`.
    fn read_subspace_val_with_height(
        &self,
        key: &Key,
        height: BlockHeight,
        last_height: BlockHeight,
    ) -> Result<Option<Vec<u8>>>;

    /// Write the value with the given height and account subspace key to the
    /// DB. Returns the size difference from previous value, if any, or the
    /// size of the value otherwise.
    fn write_subspace_val(
        &mut self,
        height: BlockHeight,
        key: &Key,
        value: impl AsRef<[u8]>,
    ) -> Result<i64>;

    /// Delete the value with the given height and account subspace key from the
    /// DB. Returns the size of the removed value, if any, 0 if no previous
    /// value was found.
    fn delete_subspace_val(
        &mut self,
        height: BlockHeight,
        key: &Key,
    ) -> Result<i64>;

    /// Start write batch.
    fn batch() -> Self::WriteBatch;

    /// Execute write batch.
    fn exec_batch(&mut self, batch: Self::WriteBatch) -> Result<()>;

    /// Batch write the value with the given height and account subspace key to
    /// the DB. Returns the size difference from previous value, if any, or
    /// the size of the value otherwise.
    fn batch_write_subspace_val(
        &self,
        batch: &mut Self::WriteBatch,
        height: BlockHeight,
        key: &Key,
        value: impl AsRef<[u8]>,
    ) -> Result<i64>;

    /// Batch delete the value with the given height and account subspace key
    /// from the DB. Returns the size of the removed value, if any, 0 if no
    /// previous value was found.
    fn batch_delete_subspace_val(
        &self,
        batch: &mut Self::WriteBatch,
        height: BlockHeight,
        key: &Key,
    ) -> Result<i64>;
}

/// A database prefix iterator.
pub trait DBIter<'iter> {
    /// The concrete type of the iterator
    type PrefixIter: Debug + Iterator<Item = (String, Vec<u8>, u64)>;

    /// WARNING: This only works for values that have been committed to DB.
    /// To be able to see values written or deleted, but not yet committed,
    /// use the `StorageWithWriteLog`.
    ///
    /// Read account subspace key value pairs with the given prefix from the DB,
    /// ordered by the storage keys.
    fn iter_prefix(&'iter self, prefix: &Key) -> Self::PrefixIter;

    /// Read results subspace key value pairs from the DB
    fn iter_results(&'iter self) -> Self::PrefixIter;
}

/// Atomic batch write.
pub trait DBWriteBatch {
    /// Insert a value into the database under the given key.
    fn put<K, V>(&mut self, key: K, value: V)
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>;

    /// Removes the database entry for key. Does nothing if the key was not
    /// found.
    fn delete<K: AsRef<[u8]>>(&mut self, key: K);
}

impl<D, H> Storage<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// open up a new instance of the storage given path to db and chain id
    pub fn open(
        db_path: impl AsRef<std::path::Path>,
        chain_id: ChainId,
        native_token: Address,
        cache: Option<&D::Cache>,
    ) -> Self {
        let block = BlockStorage {
            tree: MerkleTree::default(),
            hash: BlockHash::default(),
            height: BlockHeight::default(),
            epoch: Epoch::default(),
            pred_epochs: Epochs::default(),
            results: BlockResults::default(),
        };
        Storage::<D, H> {
            db: D::open(db_path, cache),
            chain_id,
            block,
            header: None,
            last_height: BlockHeight(0),
            last_epoch: Epoch::default(),
            next_epoch_min_start_height: BlockHeight::default(),
            next_epoch_min_start_time: DateTimeUtc::now(),
            address_gen: EstablishedAddressGen::new(
                "Privacy is a function of liberty.",
            ),
            epoch_update_tracker: (false, 0),
            tx_index: TxIndex::default(),
            conversion_state: ConversionState::default(),
            #[cfg(feature = "ferveo-tpke")]
            tx_queue: TxQueue::default(),
            native_token,
        }
    }

    /// Load the full state at the last committed height, if any. Returns the
    /// Merkle root hash and the height of the committed block.
    pub fn load_last_state(&mut self) -> Result<()> {
        if let Some(BlockStateRead {
            merkle_tree_stores,
            hash,
            height,
            epoch,
            pred_epochs,
            next_epoch_min_start_height,
            next_epoch_min_start_time,
            results,
            address_gen,
            #[cfg(feature = "ferveo-tpke")]
            tx_queue,
        }) = self.db.read_last_block()?
        {
            self.block.tree = MerkleTree::new(merkle_tree_stores);
            self.block.hash = hash;
            self.block.height = height;
            self.block.epoch = epoch;
            self.block.results = results;
            self.block.pred_epochs = pred_epochs;
            self.last_height = height;
            self.last_epoch = epoch;
            self.next_epoch_min_start_height = next_epoch_min_start_height;
            self.next_epoch_min_start_time = next_epoch_min_start_time;
            self.address_gen = address_gen;
            if self.last_epoch.0 > 1 {
                // The derived conversions will be placed in MASP address space
                let masp_addr = masp();
                let key_prefix: Key = masp_addr.to_db_key().into();
                // Load up the conversions currently being given as query
                // results
                let state_key = key_prefix
                    .push(&(token::CONVERSION_KEY_PREFIX.to_owned()))
                    .map_err(Error::KeyError)?;
                self.conversion_state = types::decode(
                    self.read(&state_key)
                        .expect("unable to read conversion state")
                        .0
                        .expect("unable to find conversion state"),
                )
                .expect("unable to decode conversion state")
            }
            #[cfg(feature = "ferveo-tpke")]
            {
                self.tx_queue = tx_queue;
            }
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
            Some((self.block.tree.root(), self.block.height.0))
        } else {
            None
        }
    }

    /// Persist the current block's state to the database
    pub fn commit_block(&mut self) -> Result<()> {
        let state = BlockStateWrite {
            merkle_tree_stores: self.block.tree.stores(),
            header: self.header.as_ref(),
            hash: &self.block.hash,
            height: self.block.height,
            epoch: self.block.epoch,
            results: &self.block.results,
            pred_epochs: &self.block.pred_epochs,
            next_epoch_min_start_height: self.next_epoch_min_start_height,
            next_epoch_min_start_time: self.next_epoch_min_start_time,
            address_gen: &self.address_gen,
            #[cfg(feature = "ferveo-tpke")]
            tx_queue: &self.tx_queue,
        };
        self.db.write_block(state)?;
        self.last_height = self.block.height;
        self.last_epoch = self.block.epoch;
        self.header = None;
        Ok(())
    }

    /// Find the root hash of the merkle tree
    pub fn merkle_root(&self) -> MerkleRoot {
        self.block.tree.root()
    }

    /// Check if the given key is present in storage. Returns the result and the
    /// gas cost.
    pub fn has_key(&self, key: &Key) -> Result<(bool, u64)> {
        Ok((self.block.tree.has_key(key)?, key.len() as _))
    }

    /// Returns a value from the specified subspace and the gas cost
    pub fn read(&self, key: &Key) -> Result<(Option<Vec<u8>>, u64)> {
        tracing::debug!("storage read key {}", key);
        let (present, gas) = self.has_key(key)?;
        if !present {
            return Ok((None, gas));
        }

        match self.db.read_subspace_val(key)? {
            Some(v) => {
                let gas = key.len() + v.len();
                Ok((Some(v), gas as _))
            }
            None => Ok((None, key.len() as _)),
        }
    }

    /// Returns a value from the specified subspace at the given height and the
    /// gas cost
    pub fn read_with_height(
        &self,
        key: &Key,
        height: BlockHeight,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        if height >= self.last_height {
            self.read(key)
        } else {
            match self.db.read_subspace_val_with_height(
                key,
                height,
                self.last_height,
            )? {
                Some(v) => {
                    let gas = key.len() + v.len();
                    Ok((Some(v), gas as _))
                }
                None => Ok((None, key.len() as _)),
            }
        }
    }

    /// WARNING: This only works for values that have been committed to DB.
    /// To be able to see values written or deleted, but not yet committed,
    /// use the `StorageWithWriteLog`.
    ///
    /// Returns a prefix iterator, ordered by storage keys, and the gas cost.
    pub fn iter_prefix(
        &self,
        prefix: &Key,
    ) -> (<D as DBIter<'_>>::PrefixIter, u64) {
        (self.db.iter_prefix(prefix), prefix.len() as _)
    }

    /// Returns a prefix iterator and the gas cost
    pub fn iter_results(&self) -> (<D as DBIter<'_>>::PrefixIter, u64) {
        (self.db.iter_results(), 0)
    }

    /// Write a value to the specified subspace and returns the gas cost and the
    /// size difference
    pub fn write(
        &mut self,
        key: &Key,
        value: impl AsRef<[u8]>,
    ) -> Result<(u64, i64)> {
        // Note that this method is the same as `StorageWrite::write_bytes`,
        // but with gas and storage bytes len diff accounting
        tracing::debug!("storage write key {}", key,);
        let value = value.as_ref();
        self.block.tree.update(key, value)?;

        let len = value.len();
        let gas = key.len() + len;
        let size_diff =
            self.db.write_subspace_val(self.block.height, key, value)?;
        Ok((gas as _, size_diff))
    }

    /// Delete the specified subspace and returns the gas cost and the size
    /// difference
    pub fn delete(&mut self, key: &Key) -> Result<(u64, i64)> {
        // Note that this method is the same as `StorageWrite::delete`,
        // but with gas and storage bytes len diff accounting
        let mut deleted_bytes_len = 0;
        if self.has_key(key)?.0 {
            self.block.tree.delete(key)?;
            deleted_bytes_len =
                self.db.delete_subspace_val(self.block.height, key)?;
        }
        let gas = key.len() + deleted_bytes_len as usize;
        Ok((gas as _, deleted_bytes_len))
    }

    /// Set the block header.
    /// The header is not in the Merkle tree as it's tracked by Tendermint.
    /// Hence, we don't update the tree when this is set.
    pub fn set_header(&mut self, header: Header) -> Result<()> {
        self.header = Some(header);
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
        let key = if let Address::Implicit(_) = addr {
            parameters::storage::get_implicit_vp_key()
        } else {
            Key::validity_predicate(addr)
        };
        self.read(&key)
    }

    #[allow(dead_code)]
    /// Check if the given address exists on chain and return the gas cost.
    pub fn exists(&self, addr: &Address) -> Result<(bool, u64)> {
        let key = Key::validity_predicate(addr);
        self.has_key(&key)
    }

    /// Get the chain ID as a raw string
    pub fn get_chain_id(&self) -> (String, u64) {
        (self.chain_id.to_string(), CHAIN_ID_LENGTH as _)
    }

    /// Get the block height
    pub fn get_block_height(&self) -> (BlockHeight, u64) {
        (self.block.height, MIN_STORAGE_GAS)
    }

    /// Get the block hash
    pub fn get_block_hash(&self) -> (BlockHash, u64) {
        (self.block.hash.clone(), BLOCK_HASH_LENGTH as _)
    }

    /// Get the existence proof
    #[cfg(any(feature = "tendermint", feature = "tendermint-abcipp"))]
    pub fn get_existence_proof(
        &self,
        key: &Key,
        value: StorageBytes,
        height: BlockHeight,
    ) -> Result<Proof> {
        use std::array;

        if height >= self.get_block_height().0 {
            let MembershipProof::ICS23(proof) = self
                .block
                .tree
                .get_sub_tree_existence_proof(array::from_ref(key), vec![value])
                .map_err(Error::MerkleTreeError)?;
            self.block
                .tree
                .get_sub_tree_proof(key, proof)
                .map(Into::into)
                .map_err(Error::MerkleTreeError)
        } else {
            match self.db.read_merkle_tree_stores(height)? {
                Some(stores) => {
                    let tree = MerkleTree::<H>::new(stores);
                    let MembershipProof::ICS23(proof) = tree
                        .get_sub_tree_existence_proof(
                            array::from_ref(key),
                            vec![value],
                        )
                        .map_err(Error::MerkleTreeError)?;
                    tree.get_sub_tree_proof(key, proof)
                        .map(Into::into)
                        .map_err(Error::MerkleTreeError)
                }
                None => Err(Error::NoMerkleTree { height }),
            }
        }
    }

    /// Get the non-existence proof
    #[cfg(any(feature = "tendermint", feature = "tendermint-abcipp"))]
    pub fn get_non_existence_proof(
        &self,
        key: &Key,
        height: BlockHeight,
    ) -> Result<Proof> {
        if height >= self.last_height {
            self.block
                .tree
                .get_non_existence_proof(key)
                .map(Into::into)
                .map_err(Error::MerkleTreeError)
        } else {
            match self.db.read_merkle_tree_stores(height)? {
                Some(stores) => MerkleTree::<H>::new(stores)
                    .get_non_existence_proof(key)
                    .map(Into::into)
                    .map_err(Error::MerkleTreeError),
                None => Err(Error::NoMerkleTree { height }),
            }
        }
    }

    /// Get the current (yet to be committed) block epoch
    pub fn get_current_epoch(&self) -> (Epoch, u64) {
        (self.block.epoch, MIN_STORAGE_GAS)
    }

    /// Get the epoch of the last committed block
    pub fn get_last_epoch(&self) -> (Epoch, u64) {
        (self.last_epoch, MIN_STORAGE_GAS)
    }

    /// Initialize the first epoch. The first epoch begins at genesis time.
    pub fn init_genesis_epoch(
        &mut self,
        initial_height: BlockHeight,
        genesis_time: DateTimeUtc,
        parameters: &Parameters,
    ) -> Result<()> {
        let EpochDuration {
            min_num_of_blocks,
            min_duration,
        } = parameters.epoch_duration;
        self.next_epoch_min_start_height = initial_height + min_num_of_blocks;
        self.next_epoch_min_start_time = genesis_time + min_duration;
        self.update_epoch_in_merkle_tree()
    }

    /// Get the block header
    pub fn get_block_header(
        &self,
        height: Option<BlockHeight>,
    ) -> Result<(Option<Header>, u64)> {
        match height {
            Some(h) if h == self.get_block_height().0 => {
                Ok((self.header.clone(), MIN_STORAGE_GAS))
            }
            Some(h) => match self.db.read_block_header(h)? {
                Some(header) => {
                    let gas = header.encoded_len() as u64;
                    Ok((Some(header), gas))
                }
                None => Ok((None, MIN_STORAGE_GAS)),
            },
            None => Ok((self.header.clone(), MIN_STORAGE_GAS)),
        }
    }

    /// Initialize a new epoch when the current epoch is finished. Returns
    /// `true` on a new epoch.
    pub fn update_epoch(
        &mut self,
        height: BlockHeight,
        time: DateTimeUtc,
    ) -> Result<bool> {
        let (parameters, _gas) =
            parameters::read(self).expect("Couldn't read protocol parameters");

        // Check if the new epoch minimum start height and start time have been
        // fulfilled. If so, queue the next epoch to start two blocks
        // into the future so as to align validator set updates + etc with
        // tendermint. This is because tendermint has a two block delay
        // to validator changes.
        let current_epoch_duration_satisfied = height
            >= self.next_epoch_min_start_height
            && time >= self.next_epoch_min_start_time;

        if current_epoch_duration_satisfied {
            if !self.epoch_update_tracker.0 {
                self.epoch_update_tracker = (true, 2);
            } else {
                self.epoch_update_tracker =
                    (true, self.epoch_update_tracker.1 - 1);
            }
        } else if self.epoch_update_tracker.0 {
            self.epoch_update_tracker.0 = false
        }
        let new_epoch =
            self.epoch_update_tracker.0 && self.epoch_update_tracker.1 == 0;

        if new_epoch {
            // Begin a new epoch
            self.block.epoch = self.block.epoch.next();
            let EpochDuration {
                min_num_of_blocks,
                min_duration,
            } = parameters.epoch_duration;
            self.next_epoch_min_start_height = height + min_num_of_blocks;
            self.next_epoch_min_start_time = time + min_duration;
            // TODO put this into PoS parameters and pass it to tendermint
            // `consensus_params` on `InitChain` and `EndBlock`
            let evidence_max_age_num_blocks: u64 = 100000;
            self.block
                .pred_epochs
                .new_epoch(height, evidence_max_age_num_blocks);
            tracing::info!("Began a new epoch {}", self.block.epoch);
        }
        self.update_epoch_in_merkle_tree()?;
        Ok(new_epoch)
    }

    /// Get the current conversions
    pub fn get_conversion_state(&self) -> &ConversionState {
        &self.conversion_state
    }

    /// Update the merkle tree with epoch data
    fn update_epoch_in_merkle_tree(&mut self) -> Result<()> {
        let key_prefix: Key =
            Address::Internal(InternalAddress::PoS).to_db_key().into();

        let key = key_prefix
            .push(&"epoch_start_height".to_string())
            .map_err(Error::KeyError)?;
        self.block
            .tree
            .update(&key, types::encode(&self.next_epoch_min_start_height))?;

        let key = key_prefix
            .push(&"epoch_start_time".to_string())
            .map_err(Error::KeyError)?;
        self.block
            .tree
            .update(&key, types::encode(&self.next_epoch_min_start_time))?;

        let key = key_prefix
            .push(&"current_epoch".to_string())
            .map_err(Error::KeyError)?;
        self.block
            .tree
            .update(&key, types::encode(&self.block.epoch))?;

        Ok(())
    }

    /// Start write batch.
    pub fn batch() -> D::WriteBatch {
        D::batch()
    }

    /// Execute write batch.
    pub fn exec_batch(&mut self, batch: D::WriteBatch) -> Result<()> {
        self.db.exec_batch(batch)
    }

    /// Batch write the value with the given height and account subspace key to
    /// the DB. Returns the size difference from previous value, if any, or
    /// the size of the value otherwise.
    pub fn batch_write_subspace_val(
        &mut self,
        batch: &mut D::WriteBatch,
        key: &Key,
        value: impl AsRef<[u8]>,
    ) -> Result<i64> {
        let value = value.as_ref();
        self.block.tree.update(key, value)?;
        self.db
            .batch_write_subspace_val(batch, self.block.height, key, value)
    }

    /// Batch delete the value with the given height and account subspace key
    /// from the DB. Returns the size of the removed value, if any, 0 if no
    /// previous value was found.
    pub fn batch_delete_subspace_val(
        &mut self,
        batch: &mut D::WriteBatch,
        key: &Key,
    ) -> Result<i64> {
        self.block.tree.delete(key)?;
        self.db
            .batch_delete_subspace_val(batch, self.block.height, key)
    }
}

impl From<MerkleTreeError> for Error {
    fn from(error: MerkleTreeError) -> Self {
        Self::MerkleTreeError(error)
    }
}

/// Helpers for testing components that depend on storage
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::mockdb::MockDB;
    use super::*;
    use crate::ledger::storage::traits::Sha256Hasher;
    use crate::types::address;

    /// `WlStorage` with a mock DB for testing
    pub type TestWlStorage = WlStorage<MockDB, Sha256Hasher>;

    /// Storage with a mock DB for testing.
    ///
    /// Prefer to use [`TestWlStorage`], which implements
    /// `storage_api::StorageRead + StorageWrite` with properly working
    /// `prefix_iter`.
    pub type TestStorage = Storage<MockDB, Sha256Hasher>;

    impl Default for TestStorage {
        fn default() -> Self {
            let chain_id = ChainId::default();
            let tree = MerkleTree::default();
            let block = BlockStorage {
                tree,
                hash: BlockHash::default(),
                height: BlockHeight::default(),
                epoch: Epoch::default(),
                pred_epochs: Epochs::default(),
                results: BlockResults::default(),
            };
            Self {
                db: MockDB::default(),
                chain_id,
                block,
                header: None,
                last_height: BlockHeight(0),
                last_epoch: Epoch::default(),
                next_epoch_min_start_height: BlockHeight::default(),
                next_epoch_min_start_time: DateTimeUtc::now(),
                address_gen: EstablishedAddressGen::new(
                    "Test address generator seed",
                ),
                epoch_update_tracker: (false, 0),
                tx_index: TxIndex::default(),
                conversion_state: ConversionState::default(),
                #[cfg(feature = "ferveo-tpke")]
                tx_queue: TxQueue::default(),
                native_token: address::nam(),
            }
        }
    }

    #[allow(clippy::derivable_impls)]
    impl Default for TestWlStorage {
        fn default() -> Self {
            Self {
                write_log: Default::default(),
                storage: Default::default(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use proptest::prelude::*;
    use proptest::test_runner::Config;
    use rust_decimal_macros::dec;

    use super::testing::*;
    use super::*;
    use crate::ledger::parameters::{self, Parameters};
    use crate::types::time::{self, Duration};

    prop_compose! {
        /// Setup test input data with arbitrary epoch duration, epoch start
        /// height and time, and a block height and time that are greater than
        /// the epoch start height and time, and the change to be applied to
        /// the epoch duration parameters.
        fn arb_and_epoch_duration_start_and_block()
        (
            start_height in 0..1000_u64,
            start_time in 0..10000_i64,
            min_num_of_blocks in 1..10_u64,
            min_duration in 1..100_i64,
            max_expected_time_per_block in 1..100_i64,
        )
        (
            min_num_of_blocks in Just(min_num_of_blocks),
            min_duration in Just(min_duration),
            max_expected_time_per_block in Just(max_expected_time_per_block),
            start_height in Just(start_height),
            start_time in Just(start_time),
            block_height in start_height + 1..(start_height + 2 * min_num_of_blocks),
            block_time in start_time + 1..(start_time + 2 * min_duration),
            // Delta will be applied on the `min_num_of_blocks` parameter
            min_blocks_delta in -(min_num_of_blocks as i64 - 1)..5,
            // Delta will be applied on the `min_duration` parameter
            min_duration_delta in -(min_duration - 1)..50,
            // Delta will be applied on the `max_expected_time_per_block` parameter
            max_time_per_block_delta in -(max_expected_time_per_block - 1)..50,
        ) -> (EpochDuration, i64, BlockHeight, DateTimeUtc, BlockHeight, DateTimeUtc,
                i64, i64, i64) {
            let epoch_duration = EpochDuration {
                min_num_of_blocks,
                min_duration: Duration::seconds(min_duration).into(),
            };
            (epoch_duration, max_expected_time_per_block,
                BlockHeight(start_height), Utc.timestamp_opt(start_time, 0).single().expect("expected valid timestamp").into(),
                BlockHeight(block_height), Utc.timestamp_opt(block_time, 0).single().expect("expected valid timestamp").into(),
                min_blocks_delta, min_duration_delta, max_time_per_block_delta)
        }
    }

    proptest! {
        #![proptest_config(Config {
            cases: 10,
            .. Config::default()
        })]
        /// Test that:
        /// 1. When the minimum blocks have been created since the epoch
        ///    start height and minimum time passed since the epoch start time,
        ///    a new epoch must start.
        /// 2. When the epoch duration parameters change, the current epoch's
        ///    duration doesn't change, but the next one does.
        #[test]
        fn update_epoch_after_its_duration(
            (epoch_duration, max_expected_time_per_block, start_height, start_time, block_height, block_time,
            min_blocks_delta, min_duration_delta, max_time_per_block_delta)
            in arb_and_epoch_duration_start_and_block())
        {
            let mut storage = TestStorage {
                next_epoch_min_start_height:
                    start_height + epoch_duration.min_num_of_blocks,
                next_epoch_min_start_time:
                    start_time + epoch_duration.min_duration,
                ..Default::default()
            };
            let mut parameters = Parameters {
                max_proposal_bytes: Default::default(),
                epoch_duration: epoch_duration.clone(),
                max_expected_time_per_block: Duration::seconds(max_expected_time_per_block).into(),
                vp_whitelist: vec![],
                tx_whitelist: vec![],
                implicit_vp: vec![],
                epochs_per_year: 100,
                pos_gain_p: dec!(0.1),
                pos_gain_d: dec!(0.1),
                staked_ratio: dec!(0.1),
                pos_inflation_amount: 0,
                #[cfg(not(feature = "mainnet"))]
                faucet_account: None,
                #[cfg(not(feature = "mainnet"))]
                wrapper_tx_fees: None,
            };
            parameters.init_storage(&mut storage);

            let epoch_before = storage.last_epoch;
            assert_eq!(epoch_before, storage.block.epoch);

            // Try to apply the epoch update
            storage.update_epoch(block_height, block_time).unwrap();

            // Test for 1.
            if block_height.0 - start_height.0
                >= epoch_duration.min_num_of_blocks
                && time::duration_passed(
                    block_time,
                    start_time,
                    epoch_duration.min_duration,
                )
            {
                // Update will now be enqueued for 2 blocks in the future
                assert_eq!(storage.block.epoch, epoch_before);
                assert!(storage.epoch_update_tracker.0);
                assert_eq!(storage.epoch_update_tracker.1,2);

                let block_height = block_height + 1;
                let block_time = block_time + Duration::seconds(1);
                storage.update_epoch(block_height, block_time).unwrap();
                assert_eq!(storage.block.epoch, epoch_before);
                assert!(storage.epoch_update_tracker.0);
                assert_eq!(storage.epoch_update_tracker.1,1);

                let block_height = block_height + 1;
                let block_time = block_time + Duration::seconds(1);
                storage.update_epoch(block_height, block_time).unwrap();
                assert_eq!(storage.block.epoch, epoch_before.next());
                assert!(storage.epoch_update_tracker.0);
                assert_eq!(storage.epoch_update_tracker.1,0);

                assert_eq!(storage.next_epoch_min_start_height,
                    block_height + epoch_duration.min_num_of_blocks);
                assert_eq!(storage.next_epoch_min_start_time,
                    block_time + epoch_duration.min_duration);
                assert_eq!(
                    storage.block.pred_epochs.get_epoch(BlockHeight(block_height.0 - 1)),
                    Some(epoch_before));
                assert_eq!(
                    storage.block.pred_epochs.get_epoch(block_height),
                    Some(epoch_before.next()));
            } else {
                assert!(!storage.epoch_update_tracker.0);
                assert_eq!(storage.epoch_update_tracker.1,0);
                assert_eq!(storage.block.epoch, epoch_before);
                assert_eq!(
                    storage.block.pred_epochs.get_epoch(BlockHeight(block_height.0 - 1)),
                    Some(epoch_before));
                assert_eq!(
                    storage.block.pred_epochs.get_epoch(block_height),
                    Some(epoch_before));
            }
            // Last epoch should only change when the block is committed
            assert_eq!(storage.last_epoch, epoch_before);

            // Update the epoch duration parameters
            parameters.epoch_duration.min_num_of_blocks =
                (parameters.epoch_duration.min_num_of_blocks as i64 + min_blocks_delta) as u64;
            let min_duration: i64 = parameters.epoch_duration.min_duration.0 as _;
            parameters.epoch_duration.min_duration =
                Duration::seconds(min_duration + min_duration_delta).into();
            parameters.max_expected_time_per_block =
                Duration::seconds(max_expected_time_per_block + max_time_per_block_delta).into();
            parameters::update_max_expected_time_per_block_parameter(&mut storage, &parameters.max_expected_time_per_block).unwrap();
            parameters::update_epoch_parameter(&mut storage, &parameters.epoch_duration).unwrap();

            // Test for 2.
            let epoch_before = storage.block.epoch;
            let height_of_update = storage.next_epoch_min_start_height.0 ;
            let time_of_update = storage.next_epoch_min_start_time;
            let height_before_update = BlockHeight(height_of_update - 1);
            let height_of_update = BlockHeight(height_of_update);
            let time_before_update = time_of_update - Duration::seconds(1);

            // No update should happen before both epoch duration conditions are
            // satisfied
            storage.update_epoch(height_before_update, time_before_update).unwrap();
            assert_eq!(storage.block.epoch, epoch_before);
            assert!(!storage.epoch_update_tracker.0);
            assert_eq!(storage.epoch_update_tracker.1,0);
            storage.update_epoch(height_of_update, time_before_update).unwrap();
            assert_eq!(storage.block.epoch, epoch_before);
            assert!(!storage.epoch_update_tracker.0);
            assert_eq!(storage.epoch_update_tracker.1,0);
            storage.update_epoch(height_before_update, time_of_update).unwrap();
            assert_eq!(storage.block.epoch, epoch_before);
            assert!(!storage.epoch_update_tracker.0);
            assert_eq!(storage.epoch_update_tracker.1,0);

            // Update should be enqueued for 2 blocks in the future starting at or after this height and time
            storage.update_epoch(height_of_update, time_of_update).unwrap();
            assert_eq!(storage.block.epoch, epoch_before);
            assert!(storage.epoch_update_tracker.0);
            assert_eq!(storage.epoch_update_tracker.1,2);

            // Increment the block height and time to simulate new blocks now
            let height_of_update = height_of_update + 1;
            let time_of_update = time_of_update + Duration::seconds(1);
            storage.update_epoch(height_of_update, time_of_update).unwrap();
            assert_eq!(storage.block.epoch, epoch_before);
            assert!(storage.epoch_update_tracker.0);
            assert_eq!(storage.epoch_update_tracker.1,1);

            let height_of_update = height_of_update + 1;
            let time_of_update = time_of_update + Duration::seconds(1);
            storage.update_epoch(height_of_update, time_of_update).unwrap();
            assert_eq!(storage.block.epoch, epoch_before.next());
            assert!(storage.epoch_update_tracker.0);
            assert_eq!(storage.epoch_update_tracker.1,0);
            // The next epoch's minimum duration should change
            assert_eq!(storage.next_epoch_min_start_height,
                height_of_update + parameters.epoch_duration.min_num_of_blocks);
            assert_eq!(storage.next_epoch_min_start_time,
                time_of_update + parameters.epoch_duration.min_duration);

            // Increment the block height and time once more to make sure things reset
            let height_of_update = height_of_update + 1;
            let time_of_update = time_of_update + Duration::seconds(1);
            storage.update_epoch(height_of_update, time_of_update).unwrap();
            assert_eq!(storage.block.epoch, epoch_before.next());
            assert!(!storage.epoch_update_tracker.0);
            assert_eq!(storage.epoch_update_tracker.1,0);
        }
    }
}
