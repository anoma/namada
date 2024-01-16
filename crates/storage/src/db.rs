use std::fmt::Debug;

use namada_core::types::address::EstablishedAddressGen;
use namada_core::types::hash::{Error as HashError, Hash};
use namada_core::types::storage::{
    BlockHash, BlockHeight, BlockResults, Epoch, Epochs, EthEventsQueue,
    Header, Key,
};
use namada_core::types::time::DateTimeUtc;
use namada_core::types::token::ConversionState;
use namada_core::types::{ethereum_events, ethereum_structs};
use namada_merkle_tree::{
    Error as MerkleTreeError, MerkleTreeStoresRead, MerkleTreeStoresWrite,
    StoreType,
};
use thiserror::Error;

use crate::tx_queue::TxQueue;

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
    MerkleTreeError(#[from] MerkleTreeError),
    #[error("DB error: {0}")]
    DBError(String),
    #[error("Borsh (de)-serialization error: {0}")]
    BorshCodingError(std::io::Error),
    #[error("Merkle tree at the height {height} is not stored")]
    NoMerkleTree { height: BlockHeight },
    #[error("Code hash error: {0}")]
    InvalidCodeHash(HashError),
}

/// A result of a function that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// The block's state as stored in the database.
pub struct BlockStateRead {
    /// Merkle tree stores
    pub merkle_tree_stores: MerkleTreeStoresRead,
    /// Hash of the block
    pub hash: BlockHash,
    /// Height of the block
    pub height: BlockHeight,
    /// Time of the block
    pub time: DateTimeUtc,
    /// Epoch of the block
    pub epoch: Epoch,
    /// Predecessor block epochs
    pub pred_epochs: Epochs,
    /// Minimum block height at which the next epoch may start
    pub next_epoch_min_start_height: BlockHeight,
    /// Minimum block time at which the next epoch may start
    pub next_epoch_min_start_time: DateTimeUtc,
    /// Update epoch delay
    pub update_epoch_blocks_delay: Option<u32>,
    /// Established address generator
    pub address_gen: EstablishedAddressGen,
    /// Results of applying transactions
    pub results: BlockResults,
    /// The conversion state
    pub conversion_state: ConversionState,
    /// Wrapper txs to be decrypted in the next block proposal
    pub tx_queue: TxQueue,
    /// The latest block height on Ethereum processed, if
    /// the bridge is enabled.
    pub ethereum_height: Option<ethereum_structs::BlockHeight>,
    /// The queue of Ethereum events to be processed in order.
    pub eth_events_queue: EthEventsQueue,
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
    /// Time of the block
    pub time: DateTimeUtc,
    /// Epoch of the block
    pub epoch: Epoch,
    /// Predecessor block epochs
    pub pred_epochs: &'a Epochs,
    /// Minimum block height at which the next epoch may start
    pub next_epoch_min_start_height: BlockHeight,
    /// Minimum block time at which the next epoch may start
    pub next_epoch_min_start_time: DateTimeUtc,
    /// Update epoch delay
    pub update_epoch_blocks_delay: Option<u32>,
    /// Established address generator
    pub address_gen: &'a EstablishedAddressGen,
    /// Results of applying transactions
    pub results: &'a BlockResults,
    /// The conversion state
    pub conversion_state: &'a ConversionState,
    /// Wrapper txs to be decrypted in the next block proposal
    pub tx_queue: &'a TxQueue,
    /// The latest block height on Ethereum processed, if
    /// the bridge is enabled.
    pub ethereum_height: Option<&'a ethereum_structs::BlockHeight>,
    /// The queue of Ethereum events to be processed in order.
    pub eth_events_queue: &'a EthEventsQueue,
}

/// A database backend.
pub trait DB: Debug {
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
    fn read_last_block(&self) -> Result<Option<BlockStateRead>>;

    /// Write block's metadata. Merkle tree sub-stores are committed only when
    /// `is_full_commit` is `true` (typically on a beginning of a new epoch).
    fn add_block_to_batch(
        &self,
        state: BlockStateWrite,
        batch: &mut Self::WriteBatch,
        is_full_commit: bool,
    ) -> Result<()>;

    /// Read the block header with the given height from the DB
    fn read_block_header(&self, height: BlockHeight) -> Result<Option<Header>>;

    /// Read the merkle tree stores with the given epoch. If a store_type is
    /// given, it reads only the the specified tree. Otherwise, it reads all
    /// trees.
    fn read_merkle_tree_stores(
        &self,
        epoch: Epoch,
        base_height: BlockHeight,
        store_type: Option<StoreType>,
    ) -> Result<Option<MerkleTreeStoresRead>>;

    /// Check if the given replay protection entry exists
    fn has_replay_protection_entry(&self, hash: &Hash) -> Result<bool>;

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

    /// Prune Merkle tree stores at the given epoch
    fn prune_merkle_tree_store(
        &mut self,
        batch: &mut Self::WriteBatch,
        store_type: &StoreType,
        pruned_epoch: Epoch,
    ) -> Result<()>;

    /// Read the signed nonce of Bridge Pool
    fn read_bridge_pool_signed_nonce(
        &self,
        height: BlockHeight,
        last_height: BlockHeight,
    ) -> Result<Option<ethereum_events::Uint>>;

    /// Write a replay protection entry
    fn write_replay_protection_entry(
        &mut self,
        batch: &mut Self::WriteBatch,
        key: &Key,
    ) -> Result<()>;

    /// Delete a replay protection entry
    fn delete_replay_protection_entry(
        &mut self,
        batch: &mut Self::WriteBatch,
        key: &Key,
    ) -> Result<()>;
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
    fn iter_prefix(&'iter self, prefix: Option<&Key>) -> Self::PrefixIter;

    /// Read results subspace key value pairs from the DB
    fn iter_results(&'iter self) -> Self::PrefixIter;

    /// Read subspace old diffs at a given height
    fn iter_old_diffs(
        &'iter self,
        height: BlockHeight,
        prefix: Option<&'iter Key>,
    ) -> Self::PrefixIter;

    /// Read subspace new diffs at a given height
    fn iter_new_diffs(
        &'iter self,
        height: BlockHeight,
        prefix: Option<&'iter Key>,
    ) -> Self::PrefixIter;

    /// Read replay protection storage from the last block
    fn iter_replay_protection(&'iter self) -> Self::PrefixIter;
}

/// Atomic batch write.
pub trait DBWriteBatch {}
