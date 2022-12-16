//! Validity predicate environment contains functions that can be called from
//! inside validity predicates.

use borsh::BorshDeserialize;

use super::storage_api::{self, StorageRead};
use crate::types::address::Address;
use crate::types::hash::Hash;
use crate::types::key::common;
use crate::types::storage::{BlockHash, BlockHeight, Epoch, Key, TxIndex};

/// Validity predicate's environment is available for native VPs and WASM VPs
pub trait VpEnv<'view> {
    /// Storage read prefix iterator
    type PrefixIter;

    /// Type to read storage state before the transaction execution
    type Pre: StorageRead<'view, PrefixIter = Self::PrefixIter>;

    /// Type to read storage state after the transaction execution
    type Post: StorageRead<'view, PrefixIter = Self::PrefixIter>;

    /// Read storage state before the transaction execution
    fn pre(&'view self) -> Self::Pre;

    /// Read storage state after the transaction execution
    fn post(&'view self) -> Self::Post;

    /// Storage read temporary state Borsh encoded value (after tx execution).
    /// It will try to read from only the write log and then decode it if
    /// found.
    fn read_temp<T: BorshDeserialize>(
        &self,
        key: &Key,
    ) -> Result<Option<T>, storage_api::Error>;

    /// Storage read temporary state raw bytes (after tx execution). It will try
    /// to read from only the write log.
    fn read_bytes_temp(
        &self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error>;

    /// Getting the chain ID.
    fn get_chain_id(&'view self) -> Result<String, storage_api::Error>;

    /// Getting the block height. The height is that of the block to which the
    /// current transaction is being applied.
    fn get_block_height(&'view self)
    -> Result<BlockHeight, storage_api::Error>;

    /// Getting the block hash. The height is that of the block to which the
    /// current transaction is being applied.
    fn get_block_hash(&'view self) -> Result<BlockHash, storage_api::Error>;

    /// Getting the block epoch. The epoch is that of the block to which the
    /// current transaction is being applied.
    fn get_block_epoch(&'view self) -> Result<Epoch, storage_api::Error>;

    /// Get the shielded transaction index.
    fn get_tx_index(&'view self) -> Result<TxIndex, storage_api::Error>;

    /// Get the address of the native token.
    fn get_native_token(&'view self) -> Result<Address, storage_api::Error>;

    /// Storage prefix iterator, ordered by storage keys. It will try to get an
    /// iterator from the storage.
    fn iter_prefix(
        &'view self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter, storage_api::Error>;

    /// Evaluate a validity predicate with given data. The address, changed
    /// storage keys and verifiers will have the same values as the input to
    /// caller's validity predicate.
    ///
    /// If the execution fails for whatever reason, this will return `false`.
    /// Otherwise returns the result of evaluation.
    fn eval(
        &self,
        vp_code: Vec<u8>,
        input_data: Vec<u8>,
    ) -> Result<bool, storage_api::Error>;

    /// Verify a transaction signature. The signature is expected to have been
    /// produced on the encoded transaction [`crate::proto::Tx`]
    /// using [`crate::proto::Tx::sign`].
    fn verify_tx_signature(
        &self,
        pk: &common::PublicKey,
        sig: &common::Signature,
    ) -> Result<bool, storage_api::Error>;

    /// Get a tx hash
    fn get_tx_code_hash(&self) -> Result<Hash, storage_api::Error>;

    /// Verify a MASP transaction
    fn verify_masp(&self, tx: Vec<u8>) -> Result<bool, storage_api::Error>;

    // ---- Methods below have default implementation via `pre/post` ----

    /// Storage read prior state Borsh encoded value (before tx execution). It
    /// will try to read from the storage and decode it if found.
    fn read_pre<T: BorshDeserialize>(
        &'view self,
        key: &Key,
    ) -> Result<Option<T>, storage_api::Error> {
        self.pre().read(key)
    }

    /// Storage read prior state raw bytes (before tx execution). It
    /// will try to read from the storage.
    fn read_bytes_pre(
        &'view self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error> {
        self.pre().read_bytes(key)
    }

    /// Storage read posterior state Borsh encoded value (after tx execution).
    /// It will try to read from the write log first and if no entry found
    /// then from the storage and then decode it if found.
    fn read_post<T: BorshDeserialize>(
        &'view self,
        key: &Key,
    ) -> Result<Option<T>, storage_api::Error> {
        self.post().read(key)
    }

    /// Storage read posterior state raw bytes (after tx execution). It will try
    /// to read from the write log first and if no entry found then from the
    /// storage.
    fn read_bytes_post(
        &'view self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error> {
        self.post().read_bytes(key)
    }

    /// Storage `has_key` in prior state (before tx execution). It will try to
    /// read from the storage.
    fn has_key_pre(&'view self, key: &Key) -> Result<bool, storage_api::Error> {
        self.pre().has_key(key)
    }

    /// Storage `has_key` in posterior state (after tx execution). It will try
    /// to check the write log first and if no entry found then the storage.
    fn has_key_post(
        &'view self,
        key: &Key,
    ) -> Result<bool, storage_api::Error> {
        self.post().has_key(key)
    }

    /// Storage prefix iterator for prior state (before tx execution). It will
    /// try to read from the storage.
    fn iter_pre_next(
        &'view self,
        iter: &mut Self::PrefixIter,
    ) -> Result<Option<(String, Vec<u8>)>, storage_api::Error> {
        self.pre().iter_next(iter)
    }

    /// Storage prefix iterator next for posterior state (after tx execution).
    /// It will try to read from the write log first and if no entry found
    /// then from the storage.
    fn iter_post_next(
        &'view self,
        iter: &mut Self::PrefixIter,
    ) -> Result<Option<(String, Vec<u8>)>, storage_api::Error> {
        self.post().iter_next(iter)
    }
}
