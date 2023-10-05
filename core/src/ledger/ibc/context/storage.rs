//! IBC storage context

pub use ics23::ProofSpec;

use crate::ledger::storage_api::Error;
use crate::types::address::Address;
use crate::types::ibc::{IbcEvent, IbcShieldedTransfer};
use crate::types::storage::{BlockHeight, Header, Key};
use crate::types::token::DenominatedAmount;

/// IBC context trait to be implemented in integration that can read and write
pub trait IbcStorageContext {
    /// Storage read prefix iterator
    type PrefixIter<'iter>
    where
        Self: 'iter;

    /// Read IBC-related data
    fn read(&self, key: &Key) -> Result<Option<Vec<u8>>, Error>;

    /// Check if the given key is present
    fn has_key(&self, key: &Key) -> Result<bool, Error>;

    /// Read IBC-related data with a prefix
    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>, Error>;

    /// next key value pair
    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, Error>;

    /// Write IBC-related data
    fn write(&mut self, key: &Key, value: Vec<u8>) -> Result<(), Error>;

    /// Delete IBC-related data
    fn delete(&mut self, key: &Key) -> Result<(), Error>;

    /// Emit an IBC event
    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<(), Error>;

    /// Get IBC events
    fn get_ibc_events(
        &self,
        event_type: impl AsRef<str>,
    ) -> Result<Vec<IbcEvent>, Error>;

    /// Transfer token
    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), Error>;

    /// Handle masp tx
    fn handle_masp_tx(
        &mut self,
        shielded: &IbcShieldedTransfer,
    ) -> Result<(), Error>;

    /// Mint token
    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), Error>;

    /// Burn token
    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), Error>;

    /// Get the current height of this chain
    fn get_height(&self) -> Result<BlockHeight, Error>;

    /// Get the block header of this chain
    fn get_header(&self, height: BlockHeight) -> Result<Option<Header>, Error>;

    /// Logging
    fn log_string(&self, message: String);
}
