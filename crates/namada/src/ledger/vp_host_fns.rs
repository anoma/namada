//! Host functions for VPs used for both native and WASM VPs.

use std::cell::RefCell;
use std::fmt::Debug;
use std::num::TryFromIntError;

use namada_core::address::{Address, ESTABLISHED_ADDRESS_BYTES_LEN};
use namada_core::hash::{Hash, HASH_LENGTH};
use namada_core::storage::{
    BlockHash, BlockHeight, Epoch, Epochs, Header, Key, TxIndex,
    TX_INDEX_LENGTH,
};
use namada_core::validity_predicate::VpError;
use namada_gas::MEMORY_ACCESS_GAS_PER_BYTE;
use namada_state::write_log::WriteLog;
use namada_state::{write_log, DBIter, StateRead, DB};
use namada_tx::{Section, Tx};
use thiserror::Error;

use crate::ibc::IbcEvent;
use crate::ledger::gas;
use crate::ledger::gas::{GasMetering, VpGasMeter};

/// Condition that must be met for a VP to halt.
pub trait ShouldHaltVp {
    /// Determine if the execution of a validity predicate
    /// should be halted immediately. Generally, this means
    /// that a tx has run out of gas.
    fn should_halt_vp(&self) -> bool;
}

impl ShouldHaltVp for VpError {
    fn should_halt_vp(&self) -> bool {
        matches!(self, Self::OutOfGas)
    }
}

impl ShouldHaltVp for RuntimeError {
    fn should_halt_vp(&self) -> bool {
        matches!(self, Self::OutOfGas(_))
    }
}

impl ShouldHaltVp for crate::storage::Error {
    fn should_halt_vp(&self) -> bool {
        let maybe_get_err = || {
            let boxed_err = match self {
                crate::storage::Error::Custom(custom_err)
                | crate::storage::Error::CustomWithMessage(_, custom_err) => {
                    Some(custom_err)
                }
                _ => None,
            }?;

            let source_err = boxed_err.source()?;
            let downcasted_vp_rt_err: &RuntimeError =
                source_err.downcast_ref()?;

            if let RuntimeError::OutOfGas(_) = downcasted_vp_rt_err {
                Some(())
            } else {
                None
            }
        };
        maybe_get_err().is_some()
    }
}

/// These runtime errors will abort VP execution immediately
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("Out of gas: {0}")]
    OutOfGas(gas::Error),
    #[error("Storage error: {0}")]
    StorageError(namada_state::Error),
    #[error("Storage data error: {0}")]
    StorageDataError(crate::storage::Error),
    #[error("Encoding error: {0}")]
    EncodingError(std::io::Error),
    #[error("Numeric conversion error: {0}")]
    NumConversionError(TryFromIntError),
    #[error("Memory error: {0}")]
    MemoryError(Box<dyn std::error::Error + Sync + Send + 'static>),
    #[error("Trying to read a temporary value with read_post")]
    ReadTemporaryValueError,
    #[error("Trying to read a permanent value with read_temp")]
    ReadPermanentValueError,
    #[error("Invalid transaction code hash")]
    InvalidCodeHash,
    #[error("No value found in result buffer")]
    NoValueInResultBuffer,
    #[error("Invalid transaction signature")]
    InvalidTxSignature,
    #[error("The section signature is invalid: {0}")]
    InvalidSectionSignature(String),
    #[error("{0}")]
    Erased(String), // type erased error
}

/// VP environment function result
pub type EnvResult<T> = std::result::Result<T, RuntimeError>;

/// Add a gas cost incured in a validity predicate
pub fn add_gas(
    gas_meter: &RefCell<VpGasMeter>,
    used_gas: u64,
) -> EnvResult<()> {
    gas_meter.borrow_mut().consume(used_gas).map_err(|err| {
        tracing::info!("Stopping VP execution because of gas error: {}", err);
        RuntimeError::OutOfGas(err)
    })
}

/// Storage read prior state (before tx execution). It will try to read from the
/// storage.
pub fn read_pre<S>(
    gas_meter: &RefCell<VpGasMeter>,
    state: &S,
    key: &Key,
) -> EnvResult<Option<Vec<u8>>>
where
    S: StateRead + Debug,
{
    let (log_val, gas) = state.write_log().read_pre(key);
    add_gas(gas_meter, gas)?;
    match log_val {
        Some(write_log::StorageModification::Write { ref value }) => {
            Ok(Some(value.clone()))
        }
        Some(&write_log::StorageModification::Delete) => {
            // Given key has been deleted
            Ok(None)
        }
        Some(write_log::StorageModification::InitAccount {
            ref vp_code_hash,
        }) => {
            // Read the VP of a new account
            Ok(Some(vp_code_hash.to_vec()))
        }
        Some(&write_log::StorageModification::Temp { .. }) => {
            Err(RuntimeError::ReadTemporaryValueError)
        }
        None => {
            // When not found in write log, try to read from the storage
            let (value, gas) =
                state.db_read(key).map_err(RuntimeError::StorageError)?;
            add_gas(gas_meter, gas)?;
            Ok(value)
        }
    }
}

/// Storage read posterior state (after tx execution). It will try to read from
/// the write log first and if no entry found then from the storage.
pub fn read_post<S>(
    gas_meter: &RefCell<VpGasMeter>,
    state: &S,
    key: &Key,
) -> EnvResult<Option<Vec<u8>>>
where
    S: StateRead + Debug,
{
    // Try to read from the write log first
    let (log_val, gas) = state.write_log().read(key);
    add_gas(gas_meter, gas)?;
    match log_val {
        Some(write_log::StorageModification::Write { ref value }) => {
            Ok(Some(value.clone()))
        }
        Some(&write_log::StorageModification::Delete) => {
            // Given key has been deleted
            Ok(None)
        }
        Some(write_log::StorageModification::InitAccount {
            ref vp_code_hash,
        }) => {
            // Read the VP code hash of a new account
            Ok(Some(vp_code_hash.to_vec()))
        }
        Some(&write_log::StorageModification::Temp { .. }) => {
            Err(RuntimeError::ReadTemporaryValueError)
        }
        None => {
            // When not found in write log, try to read from the storage
            let (value, gas) =
                state.db_read(key).map_err(RuntimeError::StorageError)?;
            add_gas(gas_meter, gas)?;
            Ok(value)
        }
    }
}

/// Storage read temporary state (after tx execution). It will try to read from
/// only the write log.
pub fn read_temp<S>(
    gas_meter: &RefCell<VpGasMeter>,
    state: &S,
    key: &Key,
) -> EnvResult<Option<Vec<u8>>>
where
    S: StateRead + Debug,
{
    // Try to read from the write log first
    let (log_val, gas) = state.write_log().read(key);
    add_gas(gas_meter, gas)?;
    match log_val {
        Some(write_log::StorageModification::Temp { ref value }) => {
            Ok(Some(value.clone()))
        }
        None => Ok(None),
        _ => Err(RuntimeError::ReadPermanentValueError),
    }
}

/// Storage `has_key` in prior state (before tx execution). It will try to read
/// from the storage.
pub fn has_key_pre<S>(
    gas_meter: &RefCell<VpGasMeter>,
    state: &S,
    key: &Key,
) -> EnvResult<bool>
where
    S: StateRead + Debug,
{
    // Try to read from the write log first
    let (log_val, gas) = state.write_log().read_pre(key);
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
                state.db_has_key(key).map_err(RuntimeError::StorageError)?;
            add_gas(gas_meter, gas)?;
            Ok(present)
        }
    }
}

/// Storage `has_key` in posterior state (after tx execution). It will try to
/// check the write log first and if no entry found then the storage.
pub fn has_key_post<S>(
    gas_meter: &RefCell<VpGasMeter>,
    state: &S,
    key: &Key,
) -> EnvResult<bool>
where
    S: StateRead + Debug,
{
    // Try to read from the write log first
    let (log_val, gas) = state.write_log().read(key);
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
                state.db_has_key(key).map_err(RuntimeError::StorageError)?;
            add_gas(gas_meter, gas)?;
            Ok(present)
        }
    }
}

/// Getting the chain ID.
pub fn get_chain_id<S>(
    gas_meter: &RefCell<VpGasMeter>,
    state: &S,
) -> EnvResult<String>
where
    S: StateRead + Debug,
{
    let (chain_id, gas) = state.in_mem().get_chain_id();
    add_gas(gas_meter, gas)?;
    Ok(chain_id)
}

/// Getting the block height. The height is that of the block to which the
/// current transaction is being applied.
pub fn get_block_height<S>(
    gas_meter: &RefCell<VpGasMeter>,
    state: &S,
) -> EnvResult<BlockHeight>
where
    S: StateRead + Debug,
{
    let (height, gas) = state.in_mem().get_block_height();
    add_gas(gas_meter, gas)?;
    Ok(height)
}

/// Getting the block header.
pub fn get_block_header<S>(
    gas_meter: &RefCell<VpGasMeter>,
    state: &S,
    height: BlockHeight,
) -> EnvResult<Option<Header>>
where
    S: StateRead + Debug,
{
    let (header, gas) = StateRead::get_block_header(state, Some(height))
        .map_err(RuntimeError::StorageError)?;
    add_gas(gas_meter, gas)?;
    Ok(header)
}

/// Getting the block hash. The height is that of the block to which the
/// current transaction is being applied.
pub fn get_block_hash<S>(
    gas_meter: &RefCell<VpGasMeter>,
    state: &S,
) -> EnvResult<BlockHash>
where
    S: StateRead + Debug,
{
    let (hash, gas) = state.in_mem().get_block_hash();
    add_gas(gas_meter, gas)?;
    Ok(hash)
}

/// Getting the block hash. The height is that of the block to which the
/// current transaction is being applied.
pub fn get_tx_code_hash(
    gas_meter: &RefCell<VpGasMeter>,
    tx: &Tx,
) -> EnvResult<Option<Hash>> {
    add_gas(gas_meter, HASH_LENGTH as u64 * MEMORY_ACCESS_GAS_PER_BYTE)?;
    let hash = tx
        .get_section(tx.code_sechash())
        .and_then(|x| Section::code_sec(x.as_ref()))
        .map(|x| x.code.hash());
    Ok(hash)
}

/// Getting the block epoch. The epoch is that of the block to which the
/// current transaction is being applied.
pub fn get_block_epoch<S>(
    gas_meter: &RefCell<VpGasMeter>,
    state: &S,
) -> EnvResult<Epoch>
where
    S: StateRead + Debug,
{
    let (epoch, gas) = state.in_mem().get_current_epoch();
    add_gas(gas_meter, gas)?;
    Ok(epoch)
}

/// Getting the block epoch. The epoch is that of the block to which the
/// current transaction is being applied.
pub fn get_tx_index(
    gas_meter: &RefCell<VpGasMeter>,
    tx_index: &TxIndex,
) -> EnvResult<TxIndex> {
    add_gas(
        gas_meter,
        TX_INDEX_LENGTH as u64 * MEMORY_ACCESS_GAS_PER_BYTE,
    )?;
    Ok(*tx_index)
}

/// Getting the native token's address.
pub fn get_native_token<S>(
    gas_meter: &RefCell<VpGasMeter>,
    state: &S,
) -> EnvResult<Address>
where
    S: StateRead + Debug,
{
    add_gas(
        gas_meter,
        ESTABLISHED_ADDRESS_BYTES_LEN as u64 * MEMORY_ACCESS_GAS_PER_BYTE,
    )?;
    Ok(state.in_mem().native_token.clone())
}

/// Given the information about predecessor block epochs
pub fn get_pred_epochs<S>(
    gas_meter: &RefCell<VpGasMeter>,
    state: &S,
) -> EnvResult<Epochs>
where
    S: StateRead + Debug,
{
    add_gas(
        gas_meter,
        state.in_mem().block.pred_epochs.first_block_heights.len() as u64
            * 8
            * MEMORY_ACCESS_GAS_PER_BYTE,
    )?;
    Ok(state.in_mem().block.pred_epochs.clone())
}

/// Getting the IBC event.
pub fn get_ibc_events<S>(
    _gas_meter: &RefCell<VpGasMeter>,
    state: &S,
    event_type: String,
) -> EnvResult<Vec<IbcEvent>>
where
    S: StateRead + Debug,
{
    Ok(state
        .write_log()
        .get_ibc_events()
        .iter()
        .filter(|event| event.event_type == event_type)
        .cloned()
        .collect())
}

/// Storage prefix iterator for prior state (before tx execution), ordered by
/// storage keys. It will try to get an iterator from the storage.
pub fn iter_prefix_pre<'a, D>(
    gas_meter: &RefCell<VpGasMeter>,
    // We cannot use e.g. `&'a State`, because it doesn't live long
    // enough - the lifetime of the `PrefixIter` must depend on the lifetime of
    // references to the `WriteLog` and `DB`.
    write_log: &'a WriteLog,
    db: &'a D,
    prefix: &Key,
) -> EnvResult<namada_state::PrefixIter<'a, D>>
where
    D: DB + for<'iter> DBIter<'iter>,
{
    let (iter, gas) = namada_state::iter_prefix_pre(write_log, db, prefix);
    add_gas(gas_meter, gas)?;
    Ok(iter)
}

/// Storage prefix iterator for posterior state (after tx execution), ordered by
/// storage keys. It will try to get an iterator from the storage.
pub fn iter_prefix_post<'a, D>(
    gas_meter: &RefCell<VpGasMeter>,
    // We cannot use e.g. `&'a State`, because it doesn't live long
    // enough - the lifetime of the `PrefixIter` must depend on the lifetime of
    // references to the `WriteLog` and `DB`.
    write_log: &'a WriteLog,
    db: &'a D,
    prefix: &Key,
) -> EnvResult<namada_state::PrefixIter<'a, D>>
where
    D: DB + for<'iter> DBIter<'iter>,
{
    let (iter, gas) = namada_state::iter_prefix_post(write_log, db, prefix);
    add_gas(gas_meter, gas)?;
    Ok(iter)
}

/// Get the next item in a storage prefix iterator (pre or post).
pub fn iter_next<DB>(
    gas_meter: &RefCell<VpGasMeter>,
    iter: &mut namada_state::PrefixIter<DB>,
) -> EnvResult<Option<(String, Vec<u8>)>>
where
    DB: namada_state::DB + for<'iter> namada_state::DBIter<'iter>,
{
    if let Some((key, val, gas)) = iter.next() {
        add_gas(gas_meter, gas)?;
        return Ok(Some((key, val)));
    }
    Ok(None)
}
