//! Functionality to do with persisting data related to the local node

use borsh::{BorshDeserialize, BorshSerialize};

use super::{DBIter, Storage, StorageHasher, DB};
use crate::ledger::storage_api::{StorageRead, StorageWrite};
use crate::types::ethereum;
use crate::types::storage::{self, DbKeySeg};

/// Represents a value in storage which is to do with our local node, rather
/// than any specific chain.
pub trait LocalNodeValue<T: BorshSerialize + BorshDeserialize> {
    /// What the initial value for this key should be when a chain is created.
    fn initial_value(&self) -> T;
    /// The storage key under which this value is stored.
    fn key(&self) -> storage::Key;
}

/// Represents the last Ethereum block height that the Ethereum oracle fully
/// processed.
#[derive(Debug)]
pub struct EthereumOracleLastProcessedBlock;

impl LocalNodeValue<Option<ethereum::BlockHeight>>
    for EthereumOracleLastProcessedBlock
{
    fn initial_value(&self) -> Option<ethereum::BlockHeight> {
        None
    }

    fn key(&self) -> storage::Key {
        storage::Key::from(DbKeySeg::StringSeg(
            "ethereum_oracle_last_processed_block".to_string(),
        ))
    }
}

/// Ensure there is a value present for all local node values.
pub fn ensure_values_present<D, H>(storage: &mut Storage<D, H>)
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    ensure_value_present(storage, EthereumOracleLastProcessedBlock)
}

/// Ensures a value is present in storage for a local node value. If it is not
/// present, the default/initial value is written for it, otherwise it is left
/// unchanged.
pub fn ensure_value_present<D, H, T>(
    storage: &mut Storage<D, H>,
    lnv: impl LocalNodeValue<T>,
) where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
    T: BorshSerialize + BorshDeserialize + std::fmt::Debug,
{
    let initial_value = lnv.initial_value();
    let key = lnv.key();
    let (has_key, _) = storage.has_key(&key).unwrap();
    if has_key {
        let value = StorageRead::read::<T>(storage, &key)
            .expect(
                "Must always be able to read a local node value from storage, \
                 if its key exists",
            )
            .expect(
                "Must always be able to Borsh deserialize a local node value \
                 from storage if it exists",
            );
        tracing::info!(
            ?key,
            ?value,
            "Value already present for local node configuration key"
        )
    } else {
        tracing::info!(
            ?key,
            ?initial_value,
            "Writing initial value for local node configuration key"
        );
        StorageWrite::write(storage, &key, initial_value).expect(
            "Must be able to write an initial value to storage for local node \
             key",
        );
    }
}

/// Read a local node value from storage.
pub fn read_value<D, H, T>(
    storage: &Storage<D, H>,
    lnv: impl LocalNodeValue<T>,
) -> T
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
    T: BorshSerialize + BorshDeserialize,
{
    let key = lnv.key();
    StorageRead::read(storage, &key).unwrap().unwrap()
}

/// Write a local node value to storage.
pub fn write_value<D, H, T: BorshSerialize + BorshDeserialize>(
    storage: &mut Storage<D, H>,
    lnv: impl LocalNodeValue<T>,
    value: T,
) where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let key = lnv.key();
    StorageWrite::write(storage, &key, value).unwrap();
}
