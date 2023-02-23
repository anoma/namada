//! IBC storage context

use ics23::ProofSpec;

use super::super::Error;
use crate::ledger::storage_api;
use crate::types::chain::ChainId;
use crate::types::ibc::IbcEvent as NamadaIbcEvent;
use crate::types::storage::{BlockHeight, Header, Key};
use crate::types::token::Amount;

// This is needed to use `ibc::Handler::Error` with `IbcActions` in
// `tx_prelude/src/ibc.rs`
impl From<Error> for storage_api::Error {
    fn from(err: Error) -> Self {
        storage_api::Error::new(err)
    }
}

/// IBC context trait to be implemented in integration that can read and write
pub trait IbcStorageContext {
    type Error: From<Error> + core::fmt::Debug;
    /// Storage read prefix iterator
    type PrefixIter<'iter>
    where
        Self: 'iter;

    /// Read IBC-related data
    fn read(&self, key: &Key) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Read IBC-related data with a prefix
    fn iter_prefix<'iter>(
        &self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>, Self::Error>;

    /// next key value pair
    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, Self::Error>;

    /// Write IBC-related data
    fn write(
        &mut self,
        key: &Key,
        data: impl AsRef<[u8]>,
    ) -> Result<(), Self::Error>;

    /// Delete IBC-related data
    fn delete(&mut self, key: &Key) -> Result<(), Self::Error>;

    /// Emit an IBC event
    fn emit_ibc_event(
        &mut self,
        event: NamadaIbcEvent,
    ) -> Result<(), Self::Error>;

    /// Transfer token
    fn transfer_token(
        &mut self,
        src: &Key,
        dest: &Key,
        amount: Amount,
    ) -> Result<(), Self::Error>;

    /// Get the current height of this chain
    fn get_height(&self) -> Result<BlockHeight, Self::Error>;

    /// Get the block header of this chain
    fn get_header(&self, height: BlockHeight) -> Result<Header, Self::Error>;

    /// Get the chain ID
    fn get_chain_id(&self) -> Result<ChainId, Self::Error>;

    fn get_proof_specs(&self) -> Vec<ProofSpec>;
}
