//! Ledger's state storage with key-value backed store and a merkle tree

pub mod wl_storage;
pub mod write_log;

use core::fmt::Debug;
use std::cmp::Ordering;
use std::format;

use namada_core::borsh::{BorshDeserialize, BorshSerialize, BorshSerializeExt};
use namada_core::tendermint::merkle::proof::ProofOps;
use namada_core::types::address::{
    Address, EstablishedAddressGen, InternalAddress,
};
use namada_core::types::chain::{ChainId, CHAIN_ID_LENGTH};
use namada_core::types::eth_bridge_pool::is_pending_transfer_key;
use namada_core::types::hash::{Error as HashError, Hash};
pub use namada_core::types::hash::{Sha256Hasher, StorageHasher};
pub use namada_core::types::storage::{
    BlockHash, BlockHeight, BlockResults, Epoch, Epochs, EthEventsQueue,
    Header, Key, KeySeg, TxIndex, BLOCK_HASH_LENGTH, BLOCK_HEIGHT_LENGTH,
    EPOCH_TYPE_LENGTH,
};
use namada_core::types::time::DateTimeUtc;
pub use namada_core::types::token::ConversionState;
use namada_core::types::{encode, ethereum_structs, storage};
use namada_gas::{
    MEMORY_ACCESS_GAS_PER_BYTE, STORAGE_ACCESS_GAS_PER_BYTE,
    STORAGE_WRITE_GAS_PER_BYTE,
};
pub use namada_merkle_tree::{
    self as merkle_tree, ics23_specs, MembershipProof, MerkleTree,
    MerkleTreeStoresRead, MerkleTreeStoresWrite, StoreRef, StoreType,
};
use namada_merkle_tree::{Error as MerkleTreeError, MerkleRoot};
use namada_parameters::{self, EpochDuration, Parameters};
pub use namada_storage::{Error as StorageError, Result as StorageResult, *};
use thiserror::Error;
use tx_queue::{ExpiredTxsQueue, TxQueue};
pub use wl_storage::{
    iter_prefix_post, iter_prefix_pre, PrefixIter, TempWlStorage, WlStorage,
};

/// A result of a function that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// We delay epoch change 2 blocks to keep it in sync with Tendermint, because
/// it has 2 blocks delay on validator set update.
pub const EPOCH_SWITCH_BLOCKS_DELAY: u32 = 2;

/// The ledger's state
#[derive(Debug)]
pub struct State<D, H>
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
    /// The most recently committed block, if any.
    pub last_block: Option<LastBlock>,
    /// The epoch of the most recently committed block. If it is `Epoch(0)`,
    /// then no block may have been committed for this chain yet.
    pub last_epoch: Epoch,
    /// Minimum block height at which the next epoch may start
    pub next_epoch_min_start_height: BlockHeight,
    /// Minimum block time at which the next epoch may start
    pub next_epoch_min_start_time: DateTimeUtc,
    /// The current established address generator
    pub address_gen: EstablishedAddressGen,
    /// We delay the switch to a new epoch by the number of blocks set in here.
    /// This is `Some` when minimum number of blocks has been created and
    /// minimum time has passed since the beginning of the last epoch.
    /// Once the value is `Some(0)`, we're ready to switch to a new epoch and
    /// this is reset back to `None`.
    pub update_epoch_blocks_delay: Option<u32>,
    /// The shielded transaction index
    pub tx_index: TxIndex,
    /// The currently saved conversion state
    pub conversion_state: ConversionState,
    /// Wrapper txs to be decrypted in the next block proposal
    pub tx_queue: TxQueue,
    /// Queue of expired transactions that need to be retransmitted.
    ///
    /// These transactions do not need to be persisted, as they are
    /// retransmitted at the **COMMIT** phase immediately following
    /// the block when they were queued.
    pub expired_txs_queue: ExpiredTxsQueue,
    /// The latest block height on Ethereum processed, if
    /// the bridge is enabled.
    pub ethereum_height: Option<ethereum_structs::BlockHeight>,
    /// The queue of Ethereum events to be processed in order.
    pub eth_events_queue: EthEventsQueue,
    /// How many block heights in the past can the storage be queried
    pub storage_read_past_height_limit: Option<u64>,
    /// Static merkle tree storage key filter
    pub merkle_tree_key_filter: fn(&storage::Key) -> bool,
}

/// Last committed block
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct LastBlock {
    /// Block height
    pub height: BlockHeight,
    /// Block hash
    pub hash: BlockHash,
    /// Block time
    pub time: DateTimeUtc,
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
    /// height of the most recently committed block, or `BlockHeight::sentinel`
    /// (0) if no block has been committed yet.
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

pub fn merklize_all_keys(_key: &storage::Key) -> bool {
    true
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("TEMPORARY error: {error}")]
    Temporary { error: String },
    #[error("Found an unknown key: {key}")]
    UnknownKey { key: String },
    #[error("Storage key error {0}")]
    KeyError(namada_core::types::storage::Error),
    #[error("Coding error: {0}")]
    CodingError(#[from] namada_core::types::DecodeError),
    #[error("Merkle tree error: {0}")]
    MerkleTreeError(MerkleTreeError),
    #[error("DB error: {0}")]
    DBError(String),
    #[error("Borsh (de)-serialization error: {0}")]
    BorshCodingError(std::io::Error),
    #[error("Merkle tree at the height {height} is not stored")]
    NoMerkleTree { height: BlockHeight },
    #[error("Code hash error: {0}")]
    InvalidCodeHash(HashError),
    #[error("DB error: {0}")]
    DbError(#[from] namada_storage::DbError),
}

impl<D, H> State<D, H>
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
        storage_read_past_height_limit: Option<u64>,
        merkle_tree_key_filter: fn(&storage::Key) -> bool,
    ) -> Self {
        let block = BlockStorage {
            tree: MerkleTree::default(),
            hash: BlockHash::default(),
            height: BlockHeight::default(),
            epoch: Epoch::default(),
            pred_epochs: Epochs::default(),
            results: BlockResults::default(),
        };
        State::<D, H> {
            db: D::open(db_path, cache),
            chain_id,
            block,
            header: None,
            last_block: None,
            last_epoch: Epoch::default(),
            next_epoch_min_start_height: BlockHeight::default(),
            next_epoch_min_start_time: DateTimeUtc::now(),
            address_gen: EstablishedAddressGen::new(
                "Privacy is a function of liberty.",
            ),
            update_epoch_blocks_delay: None,
            tx_index: TxIndex::default(),
            conversion_state: ConversionState::default(),
            tx_queue: TxQueue::default(),
            expired_txs_queue: ExpiredTxsQueue::default(),
            native_token,
            ethereum_height: None,
            eth_events_queue: EthEventsQueue::default(),
            storage_read_past_height_limit,
            merkle_tree_key_filter,
        }
    }

    /// Load the full state at the last committed height, if any. Returns the
    /// Merkle root hash and the height of the committed block.
    pub fn load_last_state(&mut self) -> Result<()> {
        if let Some(BlockStateRead {
            merkle_tree_stores,
            hash,
            height,
            time,
            epoch,
            pred_epochs,
            next_epoch_min_start_height,
            next_epoch_min_start_time,
            update_epoch_blocks_delay,
            results,
            address_gen,
            conversion_state,
            tx_queue,
            ethereum_height,
            eth_events_queue,
        }) = self.db.read_last_block()?
        {
            self.block.hash = hash.clone();
            self.block.height = height;
            self.block.epoch = epoch;
            self.block.results = results;
            self.block.pred_epochs = pred_epochs;
            self.last_block = Some(LastBlock { height, hash, time });
            self.last_epoch = epoch;
            self.next_epoch_min_start_height = next_epoch_min_start_height;
            self.next_epoch_min_start_time = next_epoch_min_start_time;
            self.update_epoch_blocks_delay = update_epoch_blocks_delay;
            self.address_gen = address_gen;
            // Rebuild Merkle tree
            self.block.tree = MerkleTree::new(merkle_tree_stores)
                .or_else(|_| self.rebuild_full_merkle_tree(height))?;
            self.conversion_state = conversion_state;
            self.tx_queue = tx_queue;
            self.ethereum_height = ethereum_height;
            self.eth_events_queue = eth_events_queue;
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
    pub fn commit_block(&mut self, mut batch: D::WriteBatch) -> Result<()> {
        // All states are written only when the first height or a new epoch
        let is_full_commit =
            self.block.height.0 == 1 || self.last_epoch != self.block.epoch;

        // For convenience in tests, fill-in a header if it's missing.
        // Normally, the header is added in `FinalizeBlock`.
        #[cfg(any(test, feature = "testing"))]
        {
            if self.header.is_none() {
                self.header = Some(Header {
                    hash: Hash::default(),
                    time: DateTimeUtc::now(),
                    next_validators_hash: Hash::default(),
                });
            }
        }

        let state = BlockStateWrite {
            merkle_tree_stores: self.block.tree.stores(),
            header: self.header.as_ref(),
            hash: &self.block.hash,
            height: self.block.height,
            time: self
                .header
                .as_ref()
                .expect("Must have a block header on commit")
                .time,
            epoch: self.block.epoch,
            results: &self.block.results,
            pred_epochs: &self.block.pred_epochs,
            next_epoch_min_start_height: self.next_epoch_min_start_height,
            next_epoch_min_start_time: self.next_epoch_min_start_time,
            update_epoch_blocks_delay: self.update_epoch_blocks_delay,
            address_gen: &self.address_gen,
            conversion_state: &self.conversion_state,
            tx_queue: &self.tx_queue,
            ethereum_height: self.ethereum_height.as_ref(),
            eth_events_queue: &self.eth_events_queue,
        };
        self.db
            .add_block_to_batch(state, &mut batch, is_full_commit)?;
        let header = self
            .header
            .take()
            .expect("Must have a block header on commit");
        self.last_block = Some(LastBlock {
            height: self.block.height,
            hash: header.hash.into(),
            time: header.time,
        });
        self.last_epoch = self.block.epoch;
        if is_full_commit {
            // prune old merkle tree stores
            self.prune_merkle_tree_stores(&mut batch)?;
        }
        self.db.exec_batch(batch)?;
        Ok(())
    }

    /// Find the root hash of the merkle tree
    pub fn merkle_root(&self) -> MerkleRoot {
        self.block.tree.root()
    }

    /// Check if the given key is present in storage. Returns the result and the
    /// gas cost.
    pub fn has_key(&self, key: &Key) -> Result<(bool, u64)> {
        Ok((
            self.db.read_subspace_val(key)?.is_some(),
            key.len() as u64 * STORAGE_ACCESS_GAS_PER_BYTE,
        ))
    }

    /// Returns a value from the specified subspace and the gas cost
    pub fn read(&self, key: &Key) -> Result<(Option<Vec<u8>>, u64)> {
        tracing::debug!("storage read key {}", key);

        match self.db.read_subspace_val(key)? {
            Some(v) => {
                let gas =
                    (key.len() + v.len()) as u64 * STORAGE_ACCESS_GAS_PER_BYTE;
                Ok((Some(v), gas))
            }
            None => Ok((None, key.len() as u64 * STORAGE_ACCESS_GAS_PER_BYTE)),
        }
    }

    /// Returns a value from the specified subspace at the given height (or the
    /// last committed height when 0) and the gas cost.
    pub fn read_with_height(
        &self,
        key: &Key,
        height: BlockHeight,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        // `0` means last committed height
        if height == BlockHeight(0) || height >= self.get_last_block_height() {
            self.read(key)
        } else {
            if !(self.merkle_tree_key_filter)(key) {
                return Ok((None, 0));
            }

            match self.db.read_subspace_val_with_height(
                key,
                height,
                self.get_last_block_height(),
            )? {
                Some(v) => {
                    let gas = (key.len() + v.len()) as u64
                        * STORAGE_ACCESS_GAS_PER_BYTE;
                    Ok((Some(v), gas))
                }
                None => {
                    Ok((None, key.len() as u64 * STORAGE_ACCESS_GAS_PER_BYTE))
                }
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
        (
            self.db.iter_prefix(Some(prefix)),
            prefix.len() as u64 * STORAGE_ACCESS_GAS_PER_BYTE,
        )
    }

    /// Returns an iterator over the block results
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
        let is_key_merklized = (self.merkle_tree_key_filter)(key);

        if is_pending_transfer_key(key) {
            // The tree of the bright pool stores the current height for the
            // pending transfer
            let height = self.block.height.serialize_to_vec();
            self.block.tree.update(key, height)?;
        } else {
            // Update the merkle tree
            if is_key_merklized {
                self.block.tree.update(key, value)?;
            }
        }

        let len = value.len();
        let gas = (key.len() + len) as u64 * STORAGE_WRITE_GAS_PER_BYTE;
        let size_diff = self.db.write_subspace_val(
            self.block.height,
            key,
            value,
            is_key_merklized,
        )?;
        Ok((gas, size_diff))
    }

    /// Delete the specified subspace and returns the gas cost and the size
    /// difference
    pub fn delete(&mut self, key: &Key) -> Result<(u64, i64)> {
        // Note that this method is the same as `StorageWrite::delete`,
        // but with gas and storage bytes len diff accounting
        let mut deleted_bytes_len = 0;
        if self.has_key(key)?.0 {
            let is_key_merklized = (self.merkle_tree_key_filter)(key);
            if is_key_merklized {
                self.block.tree.delete(key)?;
            }
            deleted_bytes_len = self.db.delete_subspace_val(
                self.block.height,
                key,
                is_key_merklized,
            )?;
        }
        let gas = (key.len() + deleted_bytes_len as usize) as u64
            * STORAGE_WRITE_GAS_PER_BYTE;
        Ok((gas, deleted_bytes_len))
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

    /// Get the hash of a validity predicate for the given account address and
    /// the gas cost for reading it.
    pub fn validity_predicate(
        &self,
        addr: &Address,
    ) -> Result<(Option<Hash>, u64)> {
        let key = if let Address::Implicit(_) = addr {
            namada_parameters::storage::get_implicit_vp_key()
        } else {
            Key::validity_predicate(addr)
        };
        match self.read(&key)? {
            (Some(value), gas) => {
                let vp_code_hash = Hash::try_from(&value[..])
                    .map_err(Error::InvalidCodeHash)?;
                Ok((Some(vp_code_hash), gas))
            }
            (None, gas) => Ok((None, gas)),
        }
    }

    #[allow(dead_code)]
    /// Check if the given address exists on chain and return the gas cost.
    pub fn exists(&self, addr: &Address) -> Result<(bool, u64)> {
        let key = Key::validity_predicate(addr);
        self.has_key(&key)
    }

    /// Get the chain ID as a raw string
    pub fn get_chain_id(&self) -> (String, u64) {
        (
            self.chain_id.to_string(),
            CHAIN_ID_LENGTH as u64 * MEMORY_ACCESS_GAS_PER_BYTE,
        )
    }

    /// Get the block height
    pub fn get_block_height(&self) -> (BlockHeight, u64) {
        (
            self.block.height,
            BLOCK_HEIGHT_LENGTH as u64 * MEMORY_ACCESS_GAS_PER_BYTE,
        )
    }

    /// Get the block hash
    pub fn get_block_hash(&self) -> (BlockHash, u64) {
        (
            self.block.hash.clone(),
            BLOCK_HASH_LENGTH as u64 * MEMORY_ACCESS_GAS_PER_BYTE,
        )
    }

    /// Rebuild full Merkle tree after [`read_last_block()`]
    fn rebuild_full_merkle_tree(
        &self,
        height: BlockHeight,
    ) -> Result<MerkleTree<H>> {
        self.get_merkle_tree(height, None)
    }

    /// Rebuild Merkle tree with diffs in the DB.
    /// Base tree and the specified `store_type` subtree is rebuilt.
    /// If `store_type` isn't given, full Merkle tree is restored.
    pub fn get_merkle_tree(
        &self,
        height: BlockHeight,
        store_type: Option<StoreType>,
    ) -> Result<MerkleTree<H>> {
        // `0` means last committed height
        let height = if height == BlockHeight(0) {
            self.get_last_block_height()
        } else {
            height
        };

        let epoch = self
            .block
            .pred_epochs
            .get_epoch(height)
            .unwrap_or(Epoch::default());
        let epoch_start_height =
            match self.block.pred_epochs.get_start_height_of_epoch(epoch) {
                Some(height) if height == BlockHeight(0) => BlockHeight(1),
                Some(height) => height,
                None => BlockHeight(1),
            };
        let stores = self
            .db
            .read_merkle_tree_stores(epoch, epoch_start_height, store_type)?
            .ok_or(Error::NoMerkleTree { height })?;
        let prefix = store_type.and_then(|st| st.provable_prefix());
        let mut tree = match store_type {
            Some(_) => MerkleTree::<H>::new_partial(stores),
            None => MerkleTree::<H>::new(stores).expect("invalid stores"),
        };
        // Restore the tree state with diffs
        let mut target_height = epoch_start_height;
        while target_height < height {
            target_height = target_height.next_height();
            let mut old_diff_iter =
                self.db.iter_old_diffs(target_height, prefix.as_ref());
            let mut new_diff_iter =
                self.db.iter_new_diffs(target_height, prefix.as_ref());

            let mut old_diff = old_diff_iter.next();
            let mut new_diff = new_diff_iter.next();
            loop {
                match (&old_diff, &new_diff) {
                    (Some(old), Some(new)) => {
                        let old_key = Key::parse(old.0.clone())
                            .expect("the key should be parsable");
                        let new_key = Key::parse(new.0.clone())
                            .expect("the key should be parsable");

                        // compare keys as String
                        match old.0.cmp(&new.0) {
                            Ordering::Equal => {
                                // the value was updated
                                if (self.merkle_tree_key_filter)(&new_key) {
                                    tree.update(
                                        &new_key,
                                        if is_pending_transfer_key(&new_key) {
                                            target_height.serialize_to_vec()
                                        } else {
                                            new.1.clone()
                                        },
                                    )?;
                                }
                                old_diff = old_diff_iter.next();
                                new_diff = new_diff_iter.next();
                            }
                            Ordering::Less => {
                                // the value was deleted
                                if (self.merkle_tree_key_filter)(&old_key) {
                                    tree.delete(&old_key)?;
                                }
                                old_diff = old_diff_iter.next();
                            }
                            Ordering::Greater => {
                                // the value was inserted
                                if (self.merkle_tree_key_filter)(&new_key) {
                                    tree.update(
                                        &new_key,
                                        if is_pending_transfer_key(&new_key) {
                                            target_height.serialize_to_vec()
                                        } else {
                                            new.1.clone()
                                        },
                                    )?;
                                }
                                new_diff = new_diff_iter.next();
                            }
                        }
                    }
                    (Some(old), None) => {
                        // the value was deleted
                        let key = Key::parse(old.0.clone())
                            .expect("the key should be parsable");

                        if (self.merkle_tree_key_filter)(&key) {
                            tree.delete(&key)?;
                        }

                        old_diff = old_diff_iter.next();
                    }
                    (None, Some(new)) => {
                        // the value was inserted
                        let key = Key::parse(new.0.clone())
                            .expect("the key should be parsable");

                        if (self.merkle_tree_key_filter)(&key) {
                            tree.update(
                                &key,
                                if is_pending_transfer_key(&key) {
                                    target_height.serialize_to_vec()
                                } else {
                                    new.1.clone()
                                },
                            )?;
                        }

                        new_diff = new_diff_iter.next();
                    }
                    (None, None) => break,
                }
            }
        }
        if let Some(st) = store_type {
            // Add the base tree with the given height
            let mut stores = self
                .db
                .read_merkle_tree_stores(epoch, height, Some(StoreType::Base))?
                .ok_or(Error::NoMerkleTree { height })?;
            let restored_stores = tree.stores();
            // Set the root and store of the rebuilt subtree
            stores.set_root(&st, *restored_stores.root(&st));
            stores.set_store(restored_stores.store(&st).to_owned());
            tree = MerkleTree::<H>::new_partial(stores);
        }
        Ok(tree)
    }

    /// Get a Tendermint-compatible existence proof.
    ///
    /// Proofs from the Ethereum bridge pool are not
    /// Tendermint-compatible. Requesting for a key
    /// belonging to the bridge pool will cause this
    /// method to error.
    pub fn get_existence_proof(
        &self,
        key: &Key,
        value: namada_merkle_tree::StorageBytes,
        height: BlockHeight,
    ) -> Result<ProofOps> {
        use std::array;

        // `0` means last committed height
        let height = if height == BlockHeight(0) {
            self.get_last_block_height()
        } else {
            height
        };

        if height > self.get_last_block_height() {
            if let MembershipProof::ICS23(proof) = self
                .block
                .tree
                .get_sub_tree_existence_proof(array::from_ref(key), vec![value])
                .map_err(Error::MerkleTreeError)?
            {
                self.block
                    .tree
                    .get_sub_tree_proof(key, proof)
                    .map(Into::into)
                    .map_err(Error::MerkleTreeError)
            } else {
                Err(Error::MerkleTreeError(MerkleTreeError::TendermintProof))
            }
        } else {
            let (store_type, _) = StoreType::sub_key(key)?;
            let tree = self.get_merkle_tree(height, Some(store_type))?;
            if let MembershipProof::ICS23(proof) = tree
                .get_sub_tree_existence_proof(array::from_ref(key), vec![value])
                .map_err(Error::MerkleTreeError)?
            {
                tree.get_sub_tree_proof(key, proof)
                    .map(Into::into)
                    .map_err(Error::MerkleTreeError)
            } else {
                Err(Error::MerkleTreeError(MerkleTreeError::TendermintProof))
            }
        }
    }

    /// Get the non-existence proof
    pub fn get_non_existence_proof(
        &self,
        key: &Key,
        height: BlockHeight,
    ) -> Result<ProofOps> {
        // `0` means last committed height
        let height = if height == BlockHeight(0) {
            self.get_last_block_height()
        } else {
            height
        };

        if height > self.get_last_block_height() {
            Err(Error::Temporary {
                error: format!(
                    "The block at the height {} hasn't committed yet",
                    height,
                ),
            })
        } else {
            let (store_type, _) = StoreType::sub_key(key)?;
            self.get_merkle_tree(height, Some(store_type))?
                .get_non_existence_proof(key)
                .map(Into::into)
                .map_err(Error::MerkleTreeError)
        }
    }

    /// Get the current (yet to be committed) block epoch
    pub fn get_current_epoch(&self) -> (Epoch, u64) {
        (
            self.block.epoch,
            EPOCH_TYPE_LENGTH as u64 * MEMORY_ACCESS_GAS_PER_BYTE,
        )
    }

    /// Get the epoch of the last committed block
    pub fn get_last_epoch(&self) -> (Epoch, u64) {
        (
            self.last_epoch,
            EPOCH_TYPE_LENGTH as u64 * MEMORY_ACCESS_GAS_PER_BYTE,
        )
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
        self.block.pred_epochs = Epochs {
            first_block_heights: vec![initial_height],
        };
        self.update_epoch_in_merkle_tree()
    }

    /// Get the block header
    pub fn get_block_header(
        &self,
        height: Option<BlockHeight>,
    ) -> Result<(Option<Header>, u64)> {
        match height {
            Some(h) if h == self.get_block_height().0 => {
                let header = self.header.clone();
                let gas = match header {
                    Some(ref header) => {
                        header.encoded_len() as u64 * MEMORY_ACCESS_GAS_PER_BYTE
                    }
                    None => MEMORY_ACCESS_GAS_PER_BYTE,
                };
                Ok((header, gas))
            }
            Some(h) => match self.db.read_block_header(h)? {
                Some(header) => {
                    let gas = header.encoded_len() as u64
                        * STORAGE_ACCESS_GAS_PER_BYTE;
                    Ok((Some(header), gas))
                }
                None => Ok((None, STORAGE_ACCESS_GAS_PER_BYTE)),
            },
            None => Ok((self.header.clone(), STORAGE_ACCESS_GAS_PER_BYTE)),
        }
    }

    /// Get the timestamp of the last committed block, or the current timestamp
    /// if no blocks have been produced yet
    pub fn get_last_block_timestamp(&self) -> Result<DateTimeUtc> {
        let last_block_height = self.get_block_height().0;

        Ok(self
            .db
            .read_block_header(last_block_height)?
            .map_or_else(DateTimeUtc::now, |header| header.time))
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
            .update(&key, encode(&self.next_epoch_min_start_height))?;

        let key = key_prefix
            .push(&"epoch_start_time".to_string())
            .map_err(Error::KeyError)?;
        self.block
            .tree
            .update(&key, encode(&self.next_epoch_min_start_time))?;

        let key = key_prefix
            .push(&"current_epoch".to_string())
            .map_err(Error::KeyError)?;
        self.block.tree.update(&key, encode(&self.block.epoch))?;

        Ok(())
    }

    /// Start write batch.
    pub fn batch() -> D::WriteBatch {
        D::batch()
    }

    /// Execute write batch.
    pub fn exec_batch(&mut self, batch: D::WriteBatch) -> Result<()> {
        Ok(self.db.exec_batch(batch)?)
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
        let is_key_merklized = (self.merkle_tree_key_filter)(key);

        if is_pending_transfer_key(key) {
            // The tree of the bridge pool stores the current height for the
            // pending transfer
            let height = self.block.height.serialize_to_vec();
            self.block.tree.update(key, height)?;
        } else {
            // Update the merkle tree
            if is_key_merklized {
                self.block.tree.update(key, value)?;
            }
        }
        Ok(self.db.batch_write_subspace_val(
            batch,
            self.block.height,
            key,
            value,
            is_key_merklized,
        )?)
    }

    /// Batch delete the value with the given height and account subspace key
    /// from the DB. Returns the size of the removed value, if any, 0 if no
    /// previous value was found.
    pub fn batch_delete_subspace_val(
        &mut self,
        batch: &mut D::WriteBatch,
        key: &Key,
    ) -> Result<i64> {
        let is_key_merklized = (self.merkle_tree_key_filter)(key);
        // Update the merkle tree
        if is_key_merklized {
            self.block.tree.delete(key)?;
        }
        Ok(self.db.batch_delete_subspace_val(
            batch,
            self.block.height,
            key,
            is_key_merklized,
        )?)
    }

    // Prune merkle tree stores. Use after updating self.block.height in the
    // commit.
    fn prune_merkle_tree_stores(
        &mut self,
        batch: &mut D::WriteBatch,
    ) -> Result<()> {
        if self.block.epoch.0 == 0 {
            return Ok(());
        }
        // Prune non-provable stores at the previous epoch
        for st in StoreType::iter_non_provable() {
            self.db.prune_merkle_tree_store(
                batch,
                st,
                self.block.epoch.prev(),
            )?;
        }
        // Prune provable stores
        let oldest_epoch = self.get_oldest_epoch();
        if oldest_epoch.0 > 0 {
            // Remove stores at the previous epoch because the Merkle tree
            // stores at the starting height of the epoch would be used to
            // restore stores at a height (> oldest_height) in the epoch
            for st in StoreType::iter_provable() {
                self.db.prune_merkle_tree_store(
                    batch,
                    st,
                    oldest_epoch.prev(),
                )?;
            }

            // Prune the BridgePool subtree stores with invalid nonce
            let mut epoch = match self.get_oldest_epoch_with_valid_nonce()? {
                Some(epoch) => epoch,
                None => return Ok(()),
            };
            while oldest_epoch < epoch {
                epoch = epoch.prev();
                self.db.prune_merkle_tree_store(
                    batch,
                    &StoreType::BridgePool,
                    epoch,
                )?;
            }
        }

        Ok(())
    }

    /// Get the height of the last committed block or 0 if no block has been
    /// committed yet. The first block is at height 1.
    pub fn get_last_block_height(&self) -> BlockHeight {
        self.last_block
            .as_ref()
            .map(|b| b.height)
            .unwrap_or_default()
    }

    /// Get the oldest epoch where we can read a value
    pub fn get_oldest_epoch(&self) -> Epoch {
        let oldest_height = match self.storage_read_past_height_limit {
            Some(limit) if limit < self.get_last_block_height().0 => {
                (self.get_last_block_height().0 - limit).into()
            }
            _ => BlockHeight(1),
        };
        self.block
            .pred_epochs
            .get_epoch(oldest_height)
            .unwrap_or_default()
    }

    /// Get oldest epoch which has the valid signed nonce of the bridge pool
    fn get_oldest_epoch_with_valid_nonce(&self) -> Result<Option<Epoch>> {
        let last_height = self.get_last_block_height();
        let current_nonce = match self
            .db
            .read_bridge_pool_signed_nonce(last_height, last_height)?
        {
            Some(nonce) => nonce,
            None => return Ok(None),
        };
        let (mut epoch, _) = self.get_last_epoch();
        // We don't need to check the older epochs because their Merkle tree
        // snapshots have been already removed
        let oldest_epoch = self.get_oldest_epoch();
        // Look up the last valid epoch which has the previous nonce of the
        // current one. It has the previous nonce, but it was
        // incremented during the epoch.
        while 0 < epoch.0 && oldest_epoch <= epoch {
            epoch = epoch.prev();
            let height =
                match self.block.pred_epochs.get_start_height_of_epoch(epoch) {
                    Some(h) => h,
                    None => continue,
                };
            let nonce = match self
                .db
                .read_bridge_pool_signed_nonce(height, last_height)?
            {
                Some(nonce) => nonce,
                // skip pruning when the old epoch doesn't have the signed nonce
                None => break,
            };
            if nonce < current_nonce {
                break;
            }
        }
        Ok(Some(epoch))
    }

    /// Check it the given transaction's hash is already present in storage
    pub fn has_replay_protection_entry(&self, hash: &Hash) -> Result<bool> {
        Ok(self.db.has_replay_protection_entry(hash)?)
    }

    /// Write the provided tx hash to storage
    pub fn write_replay_protection_entry(
        &mut self,
        batch: &mut D::WriteBatch,
        key: &Key,
    ) -> Result<()> {
        Ok(self.db.write_replay_protection_entry(batch, key)?)
    }

    /// Delete the provided tx hash from storage
    pub fn delete_replay_protection_entry(
        &mut self,
        batch: &mut D::WriteBatch,
        key: &Key,
    ) -> Result<()> {
        Ok(self.db.delete_replay_protection_entry(batch, key)?)
    }

    pub fn prune_replay_protection_buffer(
        &mut self,
        batch: &mut D::WriteBatch,
    ) -> Result<()> {
        Ok(self.db.prune_replay_protection_buffer(batch)?)
    }

    /// Iterate the replay protection storage from the last block
    pub fn iter_replay_protection(
        &self,
    ) -> Box<dyn Iterator<Item = Hash> + '_> {
        Box::new(self.db.iter_replay_protection().map(|(raw_key, _, _)| {
            raw_key.parse().expect("Failed hash conversion")
        }))
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
    use namada_core::types::address;
    use namada_core::types::hash::Sha256Hasher;

    use super::mockdb::MockDB;
    use super::*;

    /// `WlStorage` with a mock DB for testing
    pub type TestWlStorage = WlStorage<MockDB, Sha256Hasher>;

    /// Storage with a mock DB for testing.
    ///
    /// Prefer to use [`TestWlStorage`], which implements
    /// `namada_storageStorageRead + StorageWrite` with properly working
    /// `prefix_iter`.
    pub type TestStorage = State<MockDB, Sha256Hasher>;

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
                last_block: None,
                last_epoch: Epoch::default(),
                next_epoch_min_start_height: BlockHeight::default(),
                next_epoch_min_start_time: DateTimeUtc::now(),
                address_gen: EstablishedAddressGen::new(
                    "Test address generator seed",
                ),
                update_epoch_blocks_delay: None,
                tx_index: TxIndex::default(),
                conversion_state: ConversionState::default(),
                tx_queue: TxQueue::default(),
                expired_txs_queue: ExpiredTxsQueue::default(),
                native_token: address::nam(),
                ethereum_height: None,
                eth_events_queue: EthEventsQueue::default(),
                storage_read_past_height_limit: Some(1000),
                merkle_tree_key_filter: merklize_all_keys,
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
    use std::collections::BTreeMap;

    use chrono::{TimeZone, Utc};
    use namada_core::types::dec::Dec;
    use namada_core::types::time::{self, Duration};
    use namada_core::types::token;
    use namada_parameters::Parameters;
    use proptest::prelude::*;
    use proptest::test_runner::Config;

    use super::testing::*;
    use super::*;

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
            let mut wl_storage =
            TestWlStorage {
                storage: TestStorage {
                    next_epoch_min_start_height:
                        start_height + epoch_duration.min_num_of_blocks,
                    next_epoch_min_start_time:
                        start_time + epoch_duration.min_duration,
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut parameters = Parameters {
                max_tx_bytes: 1024 * 1024,
                max_proposal_bytes: Default::default(),
                max_block_gas: 20_000_000,
                epoch_duration: epoch_duration.clone(),
                max_expected_time_per_block: Duration::seconds(max_expected_time_per_block).into(),
                vp_allowlist: vec![],
                tx_allowlist: vec![],
                implicit_vp_code_hash: Some(Hash::zero()),
                epochs_per_year: 100,
                max_signatures_per_transaction: 15,
                staked_ratio: Dec::new(1,1).expect("Cannot fail"),
                pos_inflation_amount: token::Amount::zero(),
                fee_unshielding_gas_limit: 20_000,
                fee_unshielding_descriptions_limit: 15,
                minimum_gas_price: BTreeMap::default(),
            };
            namada_parameters::init_storage(&parameters, &mut wl_storage).unwrap();
            // Initialize pred_epochs to the current height
            wl_storage
                .storage
                .block
                .pred_epochs
                .new_epoch(wl_storage.storage.block.height);

            let epoch_before = wl_storage.storage.last_epoch;
            assert_eq!(epoch_before, wl_storage.storage.block.epoch);

            // Try to apply the epoch update
            wl_storage.update_epoch(block_height, block_time).unwrap();

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
                assert_eq!(wl_storage.storage.block.epoch, epoch_before);
                assert_eq!(wl_storage.storage.update_epoch_blocks_delay, Some(2));

                let block_height = block_height + 1;
                let block_time = block_time + Duration::seconds(1);
                wl_storage.update_epoch(block_height, block_time).unwrap();
                assert_eq!(wl_storage.storage.block.epoch, epoch_before);
                assert_eq!(wl_storage.storage.update_epoch_blocks_delay, Some(1));

                let block_height = block_height + 1;
                let block_time = block_time + Duration::seconds(1);
                wl_storage.update_epoch(block_height, block_time).unwrap();
                assert_eq!(wl_storage.storage.block.epoch, epoch_before.next());
                assert!(wl_storage.storage.update_epoch_blocks_delay.is_none());

                assert_eq!(wl_storage.storage.next_epoch_min_start_height,
                    block_height + epoch_duration.min_num_of_blocks);
                assert_eq!(wl_storage.storage.next_epoch_min_start_time,
                    block_time + epoch_duration.min_duration);
                assert_eq!(
                    wl_storage.storage.block.pred_epochs.get_epoch(BlockHeight(block_height.0 - 1)),
                    Some(epoch_before));
                assert_eq!(
                    wl_storage.storage.block.pred_epochs.get_epoch(block_height),
                    Some(epoch_before.next()));
            } else {
                assert!(wl_storage.storage.update_epoch_blocks_delay.is_none());
                assert_eq!(wl_storage.storage.block.epoch, epoch_before);
                assert_eq!(
                    wl_storage.storage.block.pred_epochs.get_epoch(BlockHeight(block_height.0 - 1)),
                    Some(epoch_before));
                assert_eq!(
                    wl_storage.storage.block.pred_epochs.get_epoch(block_height),
                    Some(epoch_before));
            }
            // Last epoch should only change when the block is committed
            assert_eq!(wl_storage.storage.last_epoch, epoch_before);

            // Update the epoch duration parameters
            parameters.epoch_duration.min_num_of_blocks =
                (parameters.epoch_duration.min_num_of_blocks as i64 + min_blocks_delta) as u64;
            let min_duration: i64 = parameters.epoch_duration.min_duration.0 as _;
            parameters.epoch_duration.min_duration =
                Duration::seconds(min_duration + min_duration_delta).into();
            parameters.max_expected_time_per_block =
                Duration::seconds(max_expected_time_per_block + max_time_per_block_delta).into();
            namada_parameters::update_max_expected_time_per_block_parameter(&mut wl_storage, &parameters.max_expected_time_per_block).unwrap();
            namada_parameters::update_epoch_parameter(&mut wl_storage, &parameters.epoch_duration).unwrap();

            // Test for 2.
            let epoch_before = wl_storage.storage.block.epoch;
            let height_of_update = wl_storage.storage.next_epoch_min_start_height.0 ;
            let time_of_update = wl_storage.storage.next_epoch_min_start_time;
            let height_before_update = BlockHeight(height_of_update - 1);
            let height_of_update = BlockHeight(height_of_update);
            let time_before_update = time_of_update - Duration::seconds(1);

            // No update should happen before both epoch duration conditions are
            // satisfied
            wl_storage.update_epoch(height_before_update, time_before_update).unwrap();
            assert_eq!(wl_storage.storage.block.epoch, epoch_before);
            assert!(wl_storage.storage.update_epoch_blocks_delay.is_none());
            wl_storage.update_epoch(height_of_update, time_before_update).unwrap();
            assert_eq!(wl_storage.storage.block.epoch, epoch_before);
            assert!(wl_storage.storage.update_epoch_blocks_delay.is_none());
            wl_storage.update_epoch(height_before_update, time_of_update).unwrap();
            assert_eq!(wl_storage.storage.block.epoch, epoch_before);
            assert!(wl_storage.storage.update_epoch_blocks_delay.is_none());

            // Update should be enqueued for 2 blocks in the future starting at or after this height and time
            wl_storage.update_epoch(height_of_update, time_of_update).unwrap();
            assert_eq!(wl_storage.storage.block.epoch, epoch_before);
            assert_eq!(wl_storage.storage.update_epoch_blocks_delay, Some(2));

            // Increment the block height and time to simulate new blocks now
            let height_of_update = height_of_update + 1;
            let time_of_update = time_of_update + Duration::seconds(1);
            wl_storage.update_epoch(height_of_update, time_of_update).unwrap();
            assert_eq!(wl_storage.storage.block.epoch, epoch_before);
            assert_eq!(wl_storage.storage.update_epoch_blocks_delay, Some(1));

            let height_of_update = height_of_update + 1;
            let time_of_update = time_of_update + Duration::seconds(1);
            wl_storage.update_epoch(height_of_update, time_of_update).unwrap();
            assert_eq!(wl_storage.storage.block.epoch, epoch_before.next());
            assert!(wl_storage.storage.update_epoch_blocks_delay.is_none());
            // The next epoch's minimum duration should change
            assert_eq!(wl_storage.storage.next_epoch_min_start_height,
                height_of_update + parameters.epoch_duration.min_num_of_blocks);
            assert_eq!(wl_storage.storage.next_epoch_min_start_time,
                time_of_update + parameters.epoch_duration.min_duration);

            // Increment the block height and time once more to make sure things reset
            let height_of_update = height_of_update + 1;
            let time_of_update = time_of_update + Duration::seconds(1);
            wl_storage.update_epoch(height_of_update, time_of_update).unwrap();
            assert_eq!(wl_storage.storage.block.epoch, epoch_before.next());
        }
    }

    fn test_key_1() -> Key {
        Key::parse("testing1").unwrap()
    }

    fn test_key_2() -> Key {
        Key::parse("testing2").unwrap()
    }

    fn merkle_tree_key_filter(key: &Key) -> bool {
        key == &test_key_1()
    }

    #[test]
    fn test_writing_without_merklizing_or_diffs() {
        let mut wls = TestWlStorage::default();
        assert_eq!(wls.storage.block.height.0, 0);

        (wls.storage.merkle_tree_key_filter) = merkle_tree_key_filter;

        let key1 = test_key_1();
        let val1 = 1u64;
        let key2 = test_key_2();
        let val2 = 2u64;

        // Standard write of key-val-1
        wls.write(&key1, val1).unwrap();

        // Read from WlStorage should return val1
        let res = wls.read::<u64>(&key1).unwrap().unwrap();
        assert_eq!(res, val1);

        // Read from Storage shouldn't return val1 bc the block hasn't been
        // committed
        let (res, _) = wls.storage.read(&key1).unwrap();
        assert!(res.is_none());

        // Write key-val-2 without merklizing or diffs
        wls.write(&key2, val2).unwrap();

        // Read from WlStorage should return val2
        let res = wls.read::<u64>(&key2).unwrap().unwrap();
        assert_eq!(res, val2);

        // Commit block and storage changes
        wls.commit_block().unwrap();
        wls.storage.block.height = wls.storage.block.height.next_height();

        // Read key1 from Storage should return val1
        let (res1, _) = wls.storage.read(&key1).unwrap();
        let res1 = u64::try_from_slice(&res1.unwrap()).unwrap();
        assert_eq!(res1, val1);

        // Check merkle tree inclusion of key-val-1 explicitly
        let is_merklized1 = wls.storage.block.tree.has_key(&key1).unwrap();
        assert!(is_merklized1);

        // Key2 should be in storage. Confirm by reading from
        // WlStorage and also by reading Storage subspace directly
        let res2 = wls.read::<u64>(&key2).unwrap().unwrap();
        assert_eq!(res2, val2);
        let res2 = wls.storage.db.read_subspace_val(&key2).unwrap().unwrap();
        let res2 = u64::try_from_slice(&res2).unwrap();
        assert_eq!(res2, val2);

        // Check explicitly that key-val-2 is not in merkle tree
        let is_merklized2 = wls.storage.block.tree.has_key(&key2).unwrap();
        assert!(!is_merklized2);

        // Check that the proper diffs exist for key-val-1
        let res1 = wls
            .storage
            .db
            .read_diffs_val(&key1, Default::default(), true)
            .unwrap();
        assert!(res1.is_none());

        let res1 = wls
            .storage
            .db
            .read_diffs_val(&key1, Default::default(), false)
            .unwrap()
            .unwrap();
        let res1 = u64::try_from_slice(&res1).unwrap();
        assert_eq!(res1, val1);

        // Check that there are diffs for key-val-2 in block 0, since all keys
        // need to have diffs for at least 1 block for rollback purposes
        let res2 = wls
            .storage
            .db
            .read_diffs_val(&key2, BlockHeight(0), true)
            .unwrap();
        assert!(res2.is_none());
        let res2 = wls
            .storage
            .db
            .read_diffs_val(&key2, BlockHeight(0), false)
            .unwrap()
            .unwrap();
        let res2 = u64::try_from_slice(&res2).unwrap();
        assert_eq!(res2, val2);

        // Now delete the keys properly
        wls.delete(&key1).unwrap();
        wls.delete(&key2).unwrap();

        // Commit the block again
        wls.commit_block().unwrap();
        wls.storage.block.height = wls.storage.block.height.next_height();

        // Check the key-vals are removed from the storage subspace
        let res1 = wls.read::<u64>(&key1).unwrap();
        let res2 = wls.read::<u64>(&key2).unwrap();
        assert!(res1.is_none() && res2.is_none());
        let res1 = wls.storage.db.read_subspace_val(&key1).unwrap();
        let res2 = wls.storage.db.read_subspace_val(&key2).unwrap();
        assert!(res1.is_none() && res2.is_none());

        // Check that the key-vals don't exist in the merkle tree anymore
        let is_merklized1 = wls.storage.block.tree.has_key(&key1).unwrap();
        let is_merklized2 = wls.storage.block.tree.has_key(&key2).unwrap();
        assert!(!is_merklized1 && !is_merklized2);

        // Check that key-val-1 diffs are properly updated for blocks 0 and 1
        let res1 = wls
            .storage
            .db
            .read_diffs_val(&key1, BlockHeight(0), true)
            .unwrap();
        assert!(res1.is_none());

        let res1 = wls
            .storage
            .db
            .read_diffs_val(&key1, BlockHeight(0), false)
            .unwrap()
            .unwrap();
        let res1 = u64::try_from_slice(&res1).unwrap();
        assert_eq!(res1, val1);

        let res1 = wls
            .storage
            .db
            .read_diffs_val(&key1, BlockHeight(1), true)
            .unwrap()
            .unwrap();
        let res1 = u64::try_from_slice(&res1).unwrap();
        assert_eq!(res1, val1);

        let res1 = wls
            .storage
            .db
            .read_diffs_val(&key1, BlockHeight(1), false)
            .unwrap();
        assert!(res1.is_none());

        // Check that key-val-2 diffs don't exist for block 0 anymore
        let res2 = wls
            .storage
            .db
            .read_diffs_val(&key2, BlockHeight(0), true)
            .unwrap();
        assert!(res2.is_none());
        let res2 = wls
            .storage
            .db
            .read_diffs_val(&key2, BlockHeight(0), false)
            .unwrap();
        assert!(res2.is_none());

        // Check that the block 1 diffs for key-val-2 include an "old" value of
        // val2 and no "new" value
        let res2 = wls
            .storage
            .db
            .read_diffs_val(&key2, BlockHeight(1), true)
            .unwrap()
            .unwrap();
        let res2 = u64::try_from_slice(&res2).unwrap();
        assert_eq!(res2, val2);
        let res2 = wls
            .storage
            .db
            .read_diffs_val(&key2, BlockHeight(1), false)
            .unwrap();
        assert!(res2.is_none());
    }
}
