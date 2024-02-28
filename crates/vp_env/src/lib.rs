//! Validity predicate environment contains functions that can be called from
//! inside validity predicates.

pub mod collection_validation;

// TODO: this should be re-exported from namada_shielded_token
use masp_primitives::transaction::Transaction;
use namada_core::address::Address;
use namada_core::borsh::BorshDeserialize;
use namada_core::hash::Hash;
use namada_core::ibc::{
    get_shielded_transfer, IbcEvent, MsgShieldedTransfer, EVENT_TYPE_PACKET,
};
use namada_core::storage::{
    BlockHash, BlockHeight, Epoch, Epochs, Header, Key, TxIndex,
};
use namada_core::token::Transfer;
use namada_storage::{OptionExt, ResultExt, StorageRead};
use namada_tx::Tx;

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
    ) -> Result<Option<T>, namada_storage::Error>;

    /// Storage read temporary state raw bytes (after tx execution). It will try
    /// to read from only the write log.
    fn read_bytes_temp(
        &self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, namada_storage::Error>;

    /// Getting the chain ID.
    fn get_chain_id(&self) -> Result<String, namada_storage::Error>;

    /// Getting the block height. The height is that of the block to which the
    /// current transaction is being applied.
    fn get_block_height(&self) -> Result<BlockHeight, namada_storage::Error>;

    /// Getting the block header.
    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, namada_storage::Error>;

    /// Getting the block hash. The height is that of the block to which the
    /// current transaction is being applied.
    fn get_block_hash(&self) -> Result<BlockHash, namada_storage::Error>;

    /// Getting the block epoch. The epoch is that of the block to which the
    /// current transaction is being applied.
    fn get_block_epoch(&self) -> Result<Epoch, namada_storage::Error>;

    /// Get the shielded transaction index.
    fn get_tx_index(&self) -> Result<TxIndex, namada_storage::Error>;

    /// Get the address of the native token.
    fn get_native_token(&self) -> Result<Address, namada_storage::Error>;

    /// Given the information about predecessor block epochs
    fn get_pred_epochs(&self) -> namada_storage::Result<Epochs>;

    /// Get the IBC events.
    fn get_ibc_events(
        &self,
        event_type: String,
    ) -> Result<Vec<IbcEvent>, namada_storage::Error>;

    /// Storage prefix iterator, ordered by storage keys. It will try to get an
    /// iterator from the storage.
    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>, namada_storage::Error>;

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
    ) -> Result<bool, namada_storage::Error>;

    /// Get a tx hash
    fn get_tx_code_hash(&self) -> Result<Option<Hash>, namada_storage::Error>;

    /// Get the masp tx part of the shielded action
    fn get_shielded_action(
        &self,
        tx_data: &Tx,
    ) -> Result<Transaction, namada_storage::Error> {
        let signed = tx_data;
        let data = signed.data().ok_or_err_msg("No transaction data")?;
        if let Ok(transfer) = Transfer::try_from_slice(&data) {
            let shielded_hash = transfer
                .shielded
                .ok_or_err_msg("unable to find shielded hash")?;
            let masp_tx = signed
                .get_section(&shielded_hash)
                .and_then(|x| x.as_ref().masp_tx())
                .ok_or_err_msg("unable to find shielded section")?;
            return Ok(masp_tx);
        }

        if let Ok(message) = MsgShieldedTransfer::try_from_slice(&data) {
            return Ok(message.shielded_transfer.masp_tx);
        }

        // Shielded transfer over IBC
        let events = self.get_ibc_events(EVENT_TYPE_PACKET.to_string())?;
        // The receiving event should be only one in the single IBC transaction
        let event = events.first().ok_or_else(|| {
            namada_storage::Error::new_const(
                "No IBC event for the shielded action",
            )
        })?;
        get_shielded_transfer(event)
            .into_storage_result()?
            .map(|shielded| shielded.masp_tx)
            .ok_or_else(|| {
                namada_storage::Error::new_const(
                    "No shielded transfer in the IBC event",
                )
            })
    }

    /// Charge the provided gas for the current vp
    fn charge_gas(&self, used_gas: u64) -> Result<(), namada_storage::Error>;

    // ---- Methods below have default implementation via `pre/post` ----

    /// Storage read prior state Borsh encoded value (before tx execution). It
    /// will try to read from the storage and decode it if found.
    fn read_pre<T: BorshDeserialize>(
        &'view self,
        key: &Key,
    ) -> Result<Option<T>, namada_storage::Error> {
        self.pre().read(key)
    }

    /// Storage read prior state raw bytes (before tx execution). It
    /// will try to read from the storage.
    fn read_bytes_pre(
        &'view self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, namada_storage::Error> {
        self.pre().read_bytes(key)
    }

    /// Storage read posterior state Borsh encoded value (after tx execution).
    /// It will try to read from the write log first and if no entry found
    /// then from the storage and then decode it if found.
    fn read_post<T: BorshDeserialize>(
        &'view self,
        key: &Key,
    ) -> Result<Option<T>, namada_storage::Error> {
        self.post().read(key)
    }

    /// Storage read posterior state raw bytes (after tx execution). It will try
    /// to read from the write log first and if no entry found then from the
    /// storage.
    fn read_bytes_post(
        &'view self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, namada_storage::Error> {
        self.post().read_bytes(key)
    }

    /// Storage `has_key` in prior state (before tx execution). It will try to
    /// read from the storage.
    fn has_key_pre(
        &'view self,
        key: &Key,
    ) -> Result<bool, namada_storage::Error> {
        self.pre().has_key(key)
    }

    /// Storage `has_key` in posterior state (after tx execution). It will try
    /// to check the write log first and if no entry found then the storage.
    fn has_key_post(
        &'view self,
        key: &Key,
    ) -> Result<bool, namada_storage::Error> {
        self.post().has_key(key)
    }
}
