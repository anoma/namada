//! Native VP for replay protection

use std::collections::BTreeSet;

use namada_core::ledger::storage;
use namada_core::types::address::{Address, InternalAddress};
use namada_core::types::storage::Key;
use thiserror::Error;

use crate::ledger::native_vp::{self, Ctx, NativeVp};
use crate::proto::Tx;
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
    type Error = Error;

    const ADDR: InternalAddress = InternalAddress::ReplayProtection;

    fn validate_tx(
        &self,
        _tx_data: &Tx,
        _keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        // VP should prevent any modification of the subspace.
        // Changes are only allowed from protocol
        Ok(false)
    }
}
