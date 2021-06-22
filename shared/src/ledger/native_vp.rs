//! Native validity predicate interface associated with internal accounts such
//! as the PoS and IBC modules.
use std::collections::HashSet;

use crate::ledger::gas::VpGasMeter;
use crate::ledger::storage;
use crate::ledger::storage::write_log::WriteLog;
use crate::ledger::storage::{Storage, StorageHasher};
use crate::proto::Tx;
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::Key;
use crate::vm::prefix_iter::PrefixIterators;

/// Initialize genesis storage for all the [`NativeVp`]s.
pub fn init_genesis_storage<DB, H>(_storage: &mut Storage<DB, H>)
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    // TODO
    // PoS::init_genesis_storage(storage);
    // Ibc::init_genesis_storage(storage);
}

/// A native VP module should implement this module and add its initialization
/// call to [`init_genesis_storage`].
pub trait NativeVp {
    /// The address of this VP
    const ADDR: InternalAddress;

    /// Initialize storage in the genesis block
    fn init_genesis_storage<DB, H>(storage: &mut Storage<DB, H>)
    where
        DB: storage::DB + for<'iter> storage::DBIter<'iter>,
        H: StorageHasher;

    /// Run the validity predicate. This function can call functions exposed
    /// from the [`crate::ledger::vp_env`] module using the fields from the
    /// `ctx` argument.
    fn validate_tx<DB, H>(
        ctx: &mut Ctx<DB, H>,
        tx_data: &[u8],
        keys_changed: &HashSet<Key>,
        verifiers: &HashSet<Address>,
    ) -> bool
    where
        DB: storage::DB + for<'iter> storage::DBIter<'iter>,
        H: StorageHasher;
}

/// A validity predicate's host context.
///
/// This is similar to [`anoma_shared::vm::host_env::VpCtx`], but without the VM
/// wrapper types and `eval_runner` field. The references must not be changed
/// when [`Ctx`] is mutable.
#[derive(Debug)]
pub struct Ctx<'a, DB, H>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    /// Storage prefix iterators.
    pub iterators: PrefixIterators<'a, DB>,
    /// VP gas meter.
    pub gas_meter: VpGasMeter,
    /// Read-only access to the storage.
    pub storage: &'a Storage<DB, H>,
    /// Read-only access to the write log.
    pub write_log: &'a WriteLog,
    /// The transaction code is used for signature verification
    pub tx: &'a Tx,
}

impl<'a, DB, H> Ctx<'a, DB, H>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    /// Initialize a new context for native VP call
    pub fn new(
        storage: &'a Storage<DB, H>,
        write_log: &'a WriteLog,
        tx: &'a Tx,
        gas_meter: VpGasMeter,
    ) -> Self {
        Self {
            iterators: PrefixIterators::default(),
            gas_meter,
            storage,
            write_log,
            tx,
        }
    }

    /// Read-only access to the storage.
    pub fn storage(&self) -> &'a Storage<DB, H> {
        self.storage
    }

    /// Read-only access to the write log.
    pub fn write_log(&self) -> &'a WriteLog {
        self.write_log
    }

    /// The transaction code is used for signature verification
    pub fn tx(&self) -> &'a Tx {
        self.tx
    }
}
