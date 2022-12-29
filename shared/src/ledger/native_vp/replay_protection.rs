//! Native VP for replay protection

use std::collections::BTreeSet;

use thiserror::Error;

use namada_core::ledger::{replay_protection, storage};
use namada_core::types::address::{Address, InternalAddress};
use namada_core::types::storage::Key;

use crate::ledger::native_vp::{self, Ctx, NativeVp};
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
}

/// ReplayProtection functions result
pub type Result<T> = std::result::Result<T, Error>;

/// Replay Protection VP
pub struct ReplayProtectionVp<'a, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

impl<'a, DB, H, CA> NativeVp for ReplayProtectionVp<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + storage::StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    const ADDR: InternalAddress = InternalAddress::ReplayProtection;

    type Error = Error;

    fn validate_tx(
        &self,
        _tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        // VP should prevent any modification of the subspace.
        // Changes are only allowed from protocol
        let result = keys_changed.iter().all(|key| {
            let key_type: KeyType = key.into();
            match key_type {
                KeyType::TX_HASH => false,
                KeyType::UNKNOWN => true,
            }
        });

        Ok(result)
    }
}

enum KeyType {
    #[allow(clippy::upper_case_acronyms)]
    #[allow(non_camel_case_types)]
    TX_HASH,
    #[allow(clippy::upper_case_acronyms)]
    UNKNOWN,
}

impl From<&Key> for KeyType {
    fn from(value: &Key) -> Self {
        if replay_protection::is_tx_hash_key(value) {
            KeyType::TX_HASH
        } else {
            KeyType::UNKNOWN
        }
    }
}
