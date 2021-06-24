//! Proof-of-Stake integration as a native validity predicate

use std::collections::HashSet;

use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::ledger::storage::{self, Storage, StorageHasher};
use crate::ledger::vp_env::Result;
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::Key;

/// Proof-of-Stake VP
pub struct PoS;

impl NativeVp for PoS {
    const ADDR: InternalAddress = InternalAddress::PoS;

    fn init_genesis_storage<DB, H>(_storage: &mut Storage<DB, H>)
    where
        DB: storage::DB + for<'iter> storage::DBIter<'iter>,
        H: StorageHasher,
    {
    }

    fn validate_tx<DB, H>(
        _ctx: &mut Ctx<DB, H>,
        _tx_data: &[u8],
        _keys_changed: &HashSet<Key>,
        _verifiers: &HashSet<Address>,
    ) -> Result<bool>
    where
        DB: storage::DB + for<'iter> storage::DBIter<'iter>,
        H: StorageHasher,
    {
        Ok(false)
    }
}
