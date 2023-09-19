//! Validity predicate environment contains functions that can be called from
//! inside validity predicates.

use borsh::BorshDeserialize;
use masp_primitives::transaction::Transaction;

use super::storage_api::{self, OptionExt, ResultExt, StorageRead};
use crate::proto::Tx;
use crate::types::address::Address;
use crate::types::hash::Hash;
use crate::types::ibc::{get_shielded_transfer, IbcEvent};
use crate::types::storage::{
    BlockHash, BlockHeight, Epoch, Header, Key, TxIndex,
};
use crate::types::token::Transfer;

/// Validity predicate's environment is available for native VPs and WASM VPs
pub trait VpEnv<'view>
where
    Self: 'view,
{
    /// Storage read prefix iterator
    type PrefixIter<'iter>
    where
        Self: 'iter;

    /// Type to read storage state before the transaction execution
    type Pre: StorageRead<PrefixIter<'view> = Self::PrefixIter<'view>>;

    /// Type to read storage state after the transaction execution
    type Post: StorageRead<PrefixIter<'view> = Self::PrefixIter<'view>>;

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
    fn get_chain_id(&self) -> Result<String, storage_api::Error>;

    /// Getting the block height. The height is that of the block to which the
    /// current transaction is being applied.
    fn get_block_height(&self) -> Result<BlockHeight, storage_api::Error>;

    /// Getting the block header.
    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, storage_api::Error>;

    /// Getting the block hash. The height is that of the block to which the
    /// current transaction is being applied.
    fn get_block_hash(&self) -> Result<BlockHash, storage_api::Error>;

    /// Getting the block epoch. The epoch is that of the block to which the
    /// current transaction is being applied.
    fn get_block_epoch(&self) -> Result<Epoch, storage_api::Error>;

    /// Get the shielded transaction index.
    fn get_tx_index(&self) -> Result<TxIndex, storage_api::Error>;

    /// Get the address of the native token.
    fn get_native_token(&self) -> Result<Address, storage_api::Error>;

    /// Get the IBC event.
    fn get_ibc_event(
        &self,
        event_type: String,
    ) -> Result<Option<IbcEvent>, storage_api::Error>;

    /// Storage prefix iterator, ordered by storage keys. It will try to get an
    /// iterator from the storage.
    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>, storage_api::Error>;

    /// Evaluate a validity predicate with given data. The address, changed
    /// storage keys and verifiers will have the same values as the input to
    /// caller's validity predicate.
    ///
    /// If the execution fails for whatever reason, this will return `false`.
    /// Otherwise returns the result of evaluation.
    fn eval(
        &self,
        vp_code: Hash,
        input_data: Tx,
    ) -> Result<bool, storage_api::Error>;

    /// Get a tx hash
    fn get_tx_code_hash(&self) -> Result<Option<Hash>, storage_api::Error>;

    /// Get the shielded action including the transfer and the masp tx
    fn get_shielded_action(
        &self,
        tx_data: Tx,
    ) -> Result<(Transfer, Transaction), storage_api::Error> {
        let signed = tx_data;
        match Transfer::try_from_slice(&signed.data().unwrap()[..]) {
            Ok(transfer) => {
                let shielded_hash = transfer
                    .shielded
                    .ok_or_err_msg("unable to find shielded hash")?;
                let masp_tx = signed
                    .get_section(&shielded_hash)
                    .and_then(|x| x.as_ref().masp_tx())
                    .ok_or_err_msg("unable to find shielded section")?;
                Ok((transfer, masp_tx))
            }
            Err(_) => {
                if let Some(event) =
                    self.get_ibc_event("fungible_token_packet".to_string())?
                {
                    if let Some(shielded) =
                        get_shielded_transfer(&event).into_storage_result()?
                    {
                        Ok((shielded.transfer, shielded.masp_tx))
                    } else {
                        Err(storage_api::Error::new_const(
                            "No shielded transfer in the IBC event",
                        ))
                    }
                } else {
                    Err(storage_api::Error::new_const(
                        "No IBC event for the shielded action",
                    ))
                }
            }
        }
    }

    /// Verify a MASP transaction
    fn verify_masp(&self, tx: Vec<u8>) -> Result<bool, storage_api::Error>;

    /// Charge the provided gas for the current vp
    fn charge_gas(&self, used_gas: u64) -> Result<(), storage_api::Error>;

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
}
