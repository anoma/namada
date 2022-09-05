//! Interfaces for interacting with blockchain state as part of applying a
//! protocol transaction.

use std::collections::BTreeSet;

use eyre::Result;
use namada::ledger;
use namada::ledger::pos::types::WeightedValidator;
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::types::address::Address;
use namada::types::storage::{self, Epoch};

use crate::node::ledger::shell::queries::QueriesExt;

/// Storage functionality needed for applying state changes required by a
/// protocol transaction. We don't need to know about the gas cost of changes or
/// the like as gas is not charged for protocol transactions.
pub(crate) trait Store {
    /// Returns some value stored at `key`, or `None` if no value is stored
    /// there.
    fn read(&self, key: &storage::Key) -> Result<Option<Vec<u8>>>;
    /// Check if the given key is present in storage.
    fn has_key(&self, key: &storage::Key) -> Result<bool>;
    /// Write a value to `key`
    fn write(
        &mut self,
        key: &storage::Key,
        value: impl AsRef<[u8]> + Clone,
    ) -> Result<()>;
}

/// Higher level API for the storage that might be used when applying protocol
/// transactions
pub(crate) trait StoreExt: Store {
    fn get_last_epoch(&self) -> Epoch;
    fn get_active_validators(
        &self,
        epoch: Option<Epoch>,
    ) -> BTreeSet<WeightedValidator<Address>>;
}

/// Our handle on blockchain state via a [`ledger::storage::Storage`]
pub(crate) struct LedgerStore<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    native: &'a mut ledger::storage::Storage<D, H>,
}

impl<'a, D, H> From<&'a mut ledger::storage::Storage<D, H>>
    for LedgerStore<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    fn from(native: &'a mut ledger::storage::Storage<D, H>) -> Self {
        Self { native }
    }
}

impl<'a, D, H> Store for LedgerStore<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    fn read(&self, key: &storage::Key) -> Result<Option<Vec<u8>>> {
        let (maybe_val, _) = self.native.read(key)?;
        Ok(maybe_val)
    }

    fn has_key(&self, key: &storage::Key) -> Result<bool> {
        let (has_key, _) = self.native.has_key(key)?;
        Ok(has_key)
    }

    fn write(
        &mut self,
        key: &storage::Key,
        value: impl AsRef<[u8]> + Clone,
    ) -> Result<()> {
        _ = self.native.write(key, value)?;
        Ok(())
    }
}

impl<'a, D, H> StoreExt for LedgerStore<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    fn get_last_epoch(&self) -> Epoch {
        let (last_epoch, _) = self.native.get_last_epoch();
        last_epoch
    }

    fn get_active_validators(
        &self,
        epoch: Option<Epoch>,
    ) -> BTreeSet<WeightedValidator<Address>> {
        self.native.get_active_validators(epoch)
    }
}

#[allow(missing_docs)]
/// Test helpers
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::collections::HashMap;

    use eyre::Result;
    use namada::types::storage;

    use super::*;

    /// Very simple fake storage for use in tests. In-memory map of
    /// [`storage::Key`]s to raw bytes.
    #[derive(Default)]
    pub struct FakeStore {
        pub values: HashMap<storage::Key, Vec<u8>>,
    }

    impl Store for FakeStore {
        fn read(&self, key: &storage::Key) -> Result<Option<Vec<u8>>> {
            let val = self.values.get(key);
            match val {
                Some(val) => Ok(Some(val.to_owned())),
                None => Ok(None),
            }
        }

        fn has_key(&self, key: &storage::Key) -> Result<bool> {
            Ok(self.values.contains_key(key))
        }

        fn write(
            &mut self,
            key: &storage::Key,
            value: impl AsRef<[u8]> + Clone,
        ) -> Result<()> {
            _ = self.values.insert(key.clone(), value.as_ref().to_vec());
            Ok(())
        }
    }
}
