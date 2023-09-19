//! IBC storage context

use std::fmt::Debug;

pub use ics23::ProofSpec;

use super::super::Error;
use crate::ledger::storage_api;
use crate::types::address::Address;
use crate::types::ibc::{IbcEvent, IbcShieldedTransfer};
use crate::types::storage::{BlockHeight, Header, Key};
use crate::types::token::DenominatedAmount;

// This is needed to use `ibc::Handler::Error` with `IbcActions` in
// `tx_prelude/src/ibc.rs`
impl From<Error> for storage_api::Error {
    fn from(err: Error) -> Self {
        storage_api::Error::new(err)
    }
}

/// IBC context trait to be implemented in integration that can read and write
pub trait IbcStorageContext {
    /// IBC storage error
    type Error: From<Error> + Debug;
    /// Storage read prefix iterator
    type PrefixIter<'iter>
    where
        Self: 'iter;

    /// Read IBC-related data
    fn read(&self, key: &Key) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Check if the given key is present
    fn has_key(&self, key: &Key) -> Result<bool, Self::Error>;

    /// Read IBC-related data with a prefix
    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>, Self::Error>;

    /// next key value pair
    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, Self::Error>;

    /// Write IBC-related data
    fn write(&mut self, key: &Key, value: Vec<u8>) -> Result<(), Self::Error>;

    /// Delete IBC-related data
    fn delete(&mut self, key: &Key) -> Result<(), Self::Error>;

    /// Emit an IBC event
    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<(), Self::Error>;

    /// Get an IBC event
    fn get_ibc_event(
        &self,
        event_type: impl AsRef<str>,
    ) -> Result<Option<IbcEvent>, Self::Error>;

    /// Transfer token
    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), Self::Error>;

    /// Handle masp tx
    fn handle_masp_tx(
        &mut self,
        shielded: &IbcShieldedTransfer,
    ) -> Result<(), Self::Error>;

    /// Mint token
    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), Self::Error>;

    /// Burn token
    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), Self::Error>;

    /// Get the current height of this chain
    fn get_height(&self) -> Result<BlockHeight, Self::Error>;

    /// Get the block header of this chain
    fn get_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, Self::Error>;

    /// Logging
    fn log_string(&self, message: String);
}
