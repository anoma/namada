//! Validity predicate environment contains functions that can be called from
//! inside validity predicates.

use std::num::TryFromIntError;

use borsh::BorshDeserialize;
use thiserror::Error;

use super::gas::MIN_STORAGE_GAS;
use super::storage_api::{self, StorageRead};
use crate::ledger::gas;
use crate::ledger::gas::VpGasMeter;
use crate::ledger::storage::write_log::WriteLog;
use crate::ledger::storage::{self, write_log, Storage, StorageHasher};
use crate::proto::Tx;
use crate::types::hash::Hash;
use crate::types::key::common;
use crate::types::storage::{BlockHash, BlockHeight, Epoch, Key};

/// Validity predicate's environment is available for native VPs and WASM VPs
pub trait VpEnv<'view> {
    /// Storage read prefix iterator
    type PrefixIter;

    /// Type to read storage state before the transaction execution
    type Pre: StorageRead<'view, PrefixIter = Self::PrefixIter>;

    /// Type to read storage state after the transaction execution
    type Post: StorageRead<'view, PrefixIter = Self::PrefixIter>;

    /// Read storage state before the transaction execution
    fn pre(&'view self) -> Self::Pre;

    /// Read storage state after the transaction execution
    fn post(&'view self) -> Self::Post;

    /// Storage read temporary state Borsh encoded value (after tx execution).
    /// It will try to read from only the write log and then decode it if
    /// found.
    fn read_temp<T: BorshDeserialize>(
        &self,
        key: &Key,
    ) -> Result<Option<T>, storage_api::Error>;

    /// Storage read temporary state raw bytes (after tx execution). It will try
    /// to read from only the write log.
    fn read_bytes_temp(
        &self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error>;

    /// Getting the chain ID.
    fn get_chain_id(&'view self) -> Result<String, storage_api::Error>;

    /// Getting the block height. The height is that of the block to which the
    /// current transaction is being applied.
    fn get_block_height(&'view self)
    -> Result<BlockHeight, storage_api::Error>;

    /// Getting the block hash. The height is that of the block to which the
    /// current transaction is being applied.
    fn get_block_hash(&'view self) -> Result<BlockHash, storage_api::Error>;

    /// Getting the block epoch. The epoch is that of the block to which the
    /// current transaction is being applied.
    fn get_block_epoch(&'view self) -> Result<Epoch, storage_api::Error>;

    /// Storage prefix iterator, ordered by storage keys. It will try to get an
    /// iterator from the storage.
    fn iter_prefix(
        &'view self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter, storage_api::Error>;

    /// Storage prefix iterator, reverse ordered by storage keys. It will try to
    /// get an iterator from the storage.
    fn rev_iter_prefix(
        &self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter, storage_api::Error>;

    /// Evaluate a validity predicate with given data. The address, changed
    /// storage keys and verifiers will have the same values as the input to
    /// caller's validity predicate.
    ///
    /// If the execution fails for whatever reason, this will return `false`.
    /// Otherwise returns the result of evaluation.
    fn eval(
        &self,
        vp_code: Vec<u8>,
        input_data: Vec<u8>,
    ) -> Result<bool, storage_api::Error>;

    /// Verify a transaction signature. The signature is expected to have been
    /// produced on the encoded transaction [`crate::proto::Tx`]
    /// using [`crate::proto::Tx::sign`].
    fn verify_tx_signature(
        &self,
        pk: &common::PublicKey,
        sig: &common::Signature,
    ) -> Result<bool, storage_api::Error>;

    /// Get a tx hash
    fn get_tx_code_hash(&self) -> Result<Hash, storage_api::Error>;

    // ---- Methods below have default implementation via `pre/post` ----

    /// Storage read prior state Borsh encoded value (before tx execution). It
    /// will try to read from the storage and decode it if found.
    fn read_pre<T: BorshDeserialize>(
        &'view self,
        key: &Key,
    ) -> Result<Option<T>, storage_api::Error> {
        self.pre().read(key)
    }

    /// Storage read prior state raw bytes (before tx execution). It
    /// will try to read from the storage.
    fn read_bytes_pre(
        &'view self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error> {
        self.pre().read_bytes(key)
    }

    /// Storage read posterior state Borsh encoded value (after tx execution).
    /// It will try to read from the write log first and if no entry found
    /// then from the storage and then decode it if found.
    fn read_post<T: BorshDeserialize>(
        &'view self,
        key: &Key,
    ) -> Result<Option<T>, storage_api::Error> {
        self.post().read(key)
    }

    /// Storage read posterior state raw bytes (after tx execution). It will try
    /// to read from the write log first and if no entry found then from the
    /// storage.
    fn read_bytes_post(
        &'view self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error> {
        self.post().read_bytes(key)
    }

    /// Storage `has_key` in prior state (before tx execution). It will try to
    /// read from the storage.
    fn has_key_pre(&'view self, key: &Key) -> Result<bool, storage_api::Error> {
        self.pre().has_key(key)
    }

    /// Storage `has_key` in posterior state (after tx execution). It will try
    /// to check the write log first and if no entry found then the storage.
    fn has_key_post(
        &'view self,
        key: &Key,
    ) -> Result<bool, storage_api::Error> {
        self.post().has_key(key)
    }

    /// Storage prefix iterator for prior state (before tx execution). It will
    /// try to read from the storage.
    fn iter_pre_next(
        &'view self,
        iter: &mut Self::PrefixIter,
    ) -> Result<Option<(String, Vec<u8>)>, storage_api::Error> {
        self.pre().iter_next(iter)
    }

    /// Storage prefix iterator next for posterior state (after tx execution).
    /// It will try to read from the write log first and if no entry found
    /// then from the storage.
    fn iter_post_next(
        &'view self,
        iter: &mut Self::PrefixIter,
    ) -> Result<Option<(String, Vec<u8>)>, storage_api::Error> {
        self.post().iter_next(iter)
    }
}

/// These runtime errors will abort VP execution immediately
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("Out of gas: {0}")]
    OutOfGas(gas::Error),
    #[error("Storage error: {0}")]
    StorageError(storage::Error),
    #[error("Storage data error: {0}")]
    StorageDataError(crate::types::storage::Error),
    #[error("Encoding error: {0}")]
    EncodingError(std::io::Error),
    #[error("Numeric conversion error: {0}")]
    NumConversionError(TryFromIntError),
    #[error("Memory error: {0}")]
    MemoryError(Box<dyn std::error::Error + Sync + Send + 'static>),
    #[error("Trying to read a temporary value with read_post")]
    ReadTemporaryValueError,
    #[error("Trying to read a permament value with read_temp")]
    ReadPermanentValueError,
}

/// VP environment function result
pub type EnvResult<T> = std::result::Result<T, RuntimeError>;

/// Add a gas cost incured in a validity predicate
pub fn add_gas(gas_meter: &mut VpGasMeter, used_gas: u64) -> EnvResult<()> {
    let result = gas_meter.add(used_gas).map_err(RuntimeError::OutOfGas);
    if let Err(err) = &result {
        tracing::info!("Stopping VP execution because of gas error: {}", err);
    }
    result
}

/// Storage read prior state (before tx execution). It will try to read from the
/// storage.
pub fn read_pre<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
    write_log: &WriteLog,
    key: &Key,
) -> EnvResult<Option<Vec<u8>>>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (log_val, gas) = write_log.read_pre(key);
    add_gas(gas_meter, gas)?;
    match log_val {
        Some(&write_log::StorageModification::Write { ref value }) => {
            Ok(Some(value.clone()))
        }
        Some(&write_log::StorageModification::Delete) => {
            // Given key has been deleted
            Ok(None)
        }
        Some(&write_log::StorageModification::InitAccount {
            ref vp, ..
        }) => {
            // Read the VP of a new account
            Ok(Some(vp.clone()))
        }
        Some(&write_log::StorageModification::Temp { .. }) => {
            Err(RuntimeError::ReadTemporaryValueError)
        }
        None => {
            // When not found in write log, try to read from the storage
            let (value, gas) =
                storage.read(key).map_err(RuntimeError::StorageError)?;
            add_gas(gas_meter, gas)?;
            Ok(value)
        }
    }
}

/// Storage read posterior state (after tx execution). It will try to read from
/// the write log first and if no entry found then from the storage.
pub fn read_post<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
    write_log: &WriteLog,
    key: &Key,
) -> EnvResult<Option<Vec<u8>>>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    // Try to read from the write log first
    let (log_val, gas) = write_log.read(key);
    add_gas(gas_meter, gas)?;
    match log_val {
        Some(&write_log::StorageModification::Write { ref value }) => {
            Ok(Some(value.clone()))
        }
        Some(&write_log::StorageModification::Delete) => {
            // Given key has been deleted
            Ok(None)
        }
        Some(&write_log::StorageModification::InitAccount {
            ref vp, ..
        }) => {
            // Read the VP of a new account
            Ok(Some(vp.clone()))
        }
        Some(&write_log::StorageModification::Temp { .. }) => {
            Err(RuntimeError::ReadTemporaryValueError)
        }
        None => {
            // When not found in write log, try to read from the storage
            let (value, gas) =
                storage.read(key).map_err(RuntimeError::StorageError)?;
            add_gas(gas_meter, gas)?;
            Ok(value)
        }
    }
}

/// Storage read temporary state (after tx execution). It will try to read from
/// only the write log.
pub fn read_temp(
    gas_meter: &mut VpGasMeter,
    write_log: &WriteLog,
    key: &Key,
) -> EnvResult<Option<Vec<u8>>> {
    // Try to read from the write log first
    let (log_val, gas) = write_log.read(key);
    add_gas(gas_meter, gas)?;
    match log_val {
        Some(&write_log::StorageModification::Temp { ref value }) => {
            Ok(Some(value.clone()))
        }
        None => Ok(None),
        _ => Err(RuntimeError::ReadPermanentValueError),
    }
}

/// Storage `has_key` in prior state (before tx execution). It will try to read
/// from the storage.
pub fn has_key_pre<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
    key: &Key,
) -> EnvResult<bool>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (present, gas) =
        storage.has_key(key).map_err(RuntimeError::StorageError)?;
    add_gas(gas_meter, gas)?;
    Ok(present)
}

/// Storage `has_key` in posterior state (after tx execution). It will try to
/// check the write log first and if no entry found then the storage.
pub fn has_key_post<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
    write_log: &WriteLog,
    key: &Key,
) -> EnvResult<bool>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    // Try to read from the write log first
    let (log_val, gas) = write_log.read(key);
    add_gas(gas_meter, gas)?;
    match log_val {
        Some(&write_log::StorageModification::Write { .. }) => Ok(true),
        Some(&write_log::StorageModification::Delete) => {
            // The given key has been deleted
            Ok(false)
        }
        Some(&write_log::StorageModification::InitAccount { .. }) => Ok(true),
        Some(&write_log::StorageModification::Temp { .. }) => Ok(true),
        None => {
            // When not found in write log, try to check the storage
            let (present, gas) =
                storage.has_key(key).map_err(RuntimeError::StorageError)?;
            add_gas(gas_meter, gas)?;
            Ok(present)
        }
    }
}

/// Getting the chain ID.
pub fn get_chain_id<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
) -> EnvResult<String>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (chain_id, gas) = storage.get_chain_id();
    add_gas(gas_meter, gas)?;
    Ok(chain_id)
}

/// Getting the block height. The height is that of the block to which the
/// current transaction is being applied.
pub fn get_block_height<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
) -> EnvResult<BlockHeight>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (height, gas) = storage.get_block_height();
    add_gas(gas_meter, gas)?;
    Ok(height)
}

/// Getting the block hash. The height is that of the block to which the
/// current transaction is being applied.
pub fn get_block_hash<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
) -> EnvResult<BlockHash>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (hash, gas) = storage.get_block_hash();
    add_gas(gas_meter, gas)?;
    Ok(hash)
}

/// Getting the block hash. The height is that of the block to which the
/// current transaction is being applied.
pub fn get_tx_code_hash(
    gas_meter: &mut VpGasMeter,
    tx: &Tx,
) -> EnvResult<Hash> {
    let hash = Hash(tx.code_hash());
    add_gas(gas_meter, MIN_STORAGE_GAS)?;
    Ok(hash)
}

/// Getting the block epoch. The epoch is that of the block to which the
/// current transaction is being applied.
pub fn get_block_epoch<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
) -> EnvResult<Epoch>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (epoch, gas) = storage.get_current_epoch();
    add_gas(gas_meter, gas)?;
    Ok(epoch)
}

/// Storage prefix iterator, ordered by storage keys. It will try to get an
/// iterator from the storage.
pub fn iter_prefix<'a, DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &'a Storage<DB, H>,
    prefix: &Key,
) -> EnvResult<<DB as storage::DBIter<'a>>::PrefixIter>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (iter, gas) = storage.iter_prefix(prefix);
    add_gas(gas_meter, gas)?;
    Ok(iter)
}

/// Storage prefix iterator, reverse ordered by storage keys. It will try to get
/// an iterator from the storage.
pub fn rev_iter_prefix<'a, DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &'a Storage<DB, H>,
    prefix: &Key,
) -> EnvResult<<DB as storage::DBIter<'a>>::PrefixIter>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (iter, gas) = storage.rev_iter_prefix(prefix);
    add_gas(gas_meter, gas)?;
    Ok(iter)
}

/// Storage prefix iterator for prior state (before tx execution). It will try
/// to read from the storage.
pub fn iter_pre_next<DB>(
    gas_meter: &mut VpGasMeter,
    iter: &mut <DB as storage::DBIter<'_>>::PrefixIter,
) -> EnvResult<Option<(String, Vec<u8>)>>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    if let Some((key, val, gas)) = iter.next() {
        add_gas(gas_meter, gas)?;
        return Ok(Some((key, val)));
    }
    Ok(None)
}

/// Storage prefix iterator next for posterior state (after tx execution). It
/// will try to read from the write log first and if no entry found then from
/// the storage.
pub fn iter_post_next<DB>(
    gas_meter: &mut VpGasMeter,
    write_log: &WriteLog,
    iter: &mut <DB as storage::DBIter<'_>>::PrefixIter,
) -> EnvResult<Option<(String, Vec<u8>)>>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    for (key, val, iter_gas) in iter {
        let (log_val, log_gas) = write_log.read(
            &Key::parse(key.clone()).map_err(RuntimeError::StorageDataError)?,
        );
        add_gas(gas_meter, iter_gas + log_gas)?;
        match log_val {
            Some(&write_log::StorageModification::Write { ref value }) => {
                return Ok(Some((key, value.clone())));
            }
            Some(&write_log::StorageModification::Delete) => {
                // check the next because the key has already deleted
                continue;
            }
            Some(&write_log::StorageModification::InitAccount { .. }) => {
                // a VP of a new account doesn't need to be iterated
                continue;
            }
            Some(&write_log::StorageModification::Temp { .. }) => {
                return Err(RuntimeError::ReadTemporaryValueError);
            }
            None => return Ok(Some((key, val))),
        }
    }
    Ok(None)
}
