//! Transaction environment contains functions that can be called from
//! inside a tx.

use borsh::BorshSerialize;
use namada_core::types::address::Address;
use namada_core::types::ibc::IbcEvent;
use namada_core::types::storage;
use namada_storage::{self, StorageRead, StorageWrite};

/// Transaction host functions
pub trait TxEnv: StorageRead + StorageWrite {
    /// Write a temporary value to be encoded with Borsh at the given key to
    /// storage.
    fn write_temp<T: BorshSerialize>(
        &mut self,
        key: &storage::Key,
        val: T,
    ) -> Result<(), storage_api::Error>;

    /// Write a temporary value as bytes at the given key to storage.
    fn write_bytes_temp(
        &mut self,
        key: &storage::Key,
        val: impl AsRef<[u8]>,
    ) -> Result<(), storage_api::Error>;

    /// Insert a verifier address. This address must exist on chain, otherwise
    /// the transaction will be rejected.
    ///
    /// Validity predicates of each verifier addresses inserted in the
    /// transaction will validate the transaction and will receive all the
    /// changed storage keys and initialized accounts in their inputs.
    fn insert_verifier(
        &mut self,
        addr: &Address,
    ) -> Result<(), storage_api::Error>;

    /// Initialize a new account generates a new established address and
    /// writes the given code as its validity predicate into the storage.
    fn init_account(
        &mut self,
        code_hash: impl AsRef<[u8]>,
        code_tag: &Option<String>,
    ) -> Result<Address, storage_api::Error>;

    /// Update a validity predicate
    fn update_validity_predicate(
        &mut self,
        addr: &Address,
        code: impl AsRef<[u8]>,
        code_tag: &Option<String>,
    ) -> Result<(), storage_api::Error>;

    /// Emit an IBC event. On multiple calls, these emitted event will be added.
    fn emit_ibc_event(
        &mut self,
        event: &IbcEvent,
    ) -> Result<(), storage_api::Error>;

    /// Request to charge the provided amount of gas for the current transaction
    fn charge_gas(&mut self, used_gas: u64) -> Result<(), storage_api::Error>;

    /// Get IBC events with a event type
    fn get_ibc_events(
        &self,
        event_type: impl AsRef<str>,
    ) -> Result<Vec<IbcEvent>, storage_api::Error>;

    /// Set the sentinel for an invalid section commitment
    fn set_commitment_sentinel(&mut self);
}
