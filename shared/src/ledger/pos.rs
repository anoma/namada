//! Proof-of-Stake integration as a native validity predicate

use std::collections::HashSet;

use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::ledger::storage::{self, Storage, StorageHasher};
use crate::ledger::vp_env::Result;
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::Key;

/// Proof-of-Stake VP
pub struct PoS<'a, DB, H>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H>,
}

impl<'a, DB, H> NativeVp for PoS<'a, DB, H>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    const ADDR: InternalAddress = InternalAddress::PoS;

    fn init_genesis_storage<D, SH>(_storage: &mut Storage<D, SH>)
    where
        D: storage::DB + for<'iter> storage::DBIter<'iter>,
        SH: StorageHasher,
    {
    }

    fn validate_tx(
        &self,
        _tx_data: &[u8],
        _keys_changed: &HashSet<Key>,
        _verifiers: &HashSet<Address>,
    ) -> Result<bool> {
        Ok(false)
    }
}
