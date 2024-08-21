//! IBC storage context

pub use ics23::ProofSpec;
use namada_core::address::Address;
use namada_core::token::Amount;
use namada_state::{StorageRead, StorageResult, StorageWrite};

use crate::event::IbcEvent;

/// IBC context trait to be implemented in integration that can read and write
pub trait IbcStorageContext {
    /// Storage read/write type
    type Storage: StorageRead + StorageWrite;

    /// Read-only storage access
    fn storage(&self) -> &Self::Storage;

    /// Read/write storage access
    fn storage_mut(&mut self) -> &mut Self::Storage;

    /// Emit an IBC event
    fn emit_ibc_event(&mut self, event: IbcEvent) -> StorageResult<()>;

    /// Transfer token
    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: Amount,
    ) -> StorageResult<()>;

    /// Mint token
    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> StorageResult<()>;

    /// Burn token
    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> StorageResult<()>;

    /// Insert the verifier
    fn insert_verifier(&mut self, verifier: &Address) -> StorageResult<()>;

    /// Logging
    fn log_string(&self, message: String);
}
