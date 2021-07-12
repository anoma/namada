//! Protocol parameters

use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use thiserror::Error;

use super::storage::types::decode;
use crate::ledger::native_vp::NativeVp;
use crate::ledger::storage::types::{self, encode};
use crate::ledger::storage::{self, Storage};
use crate::ledger::vp_env;
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::{DbKeySeg, Key};
use crate::types::time::DurationSecs;

/// Protocol parameters
#[derive(
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Parameters {
    /// Epoch duration
    pub epoch_duration: EpochDuration,
}

/// Epoch duration. A new epoch begins as soon as both the `min_num_of_blocks`
/// and `min_duration` have passed since the beginning of the current epoch.
#[derive(
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct EpochDuration {
    /// Minimum number of blocks in an epoch
    pub min_num_of_blocks: u32,
    /// Minimum duration of an epoch
    pub min_duration: DurationSecs,
}

/// Initialize parameters in storage in the genesis block.
pub fn init_genesis_storage<DB, H>(
    storage: &mut Storage<DB, H>,
    parameters: &Parameters,
) where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
{
    let params_key = storage_key();
    let params_value = encode(parameters);
    storage
        .write(&params_key, params_value)
        .expect("Protocol parameters must be initialized in the genesis block");
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ReadError {
    #[error("Storage error: {0}")]
    StorageError(storage::Error),
    #[error("Storage type error: {0}")]
    StorageTypeError(types::Error),
    #[error("Protocol parameters are missing, they must be always set")]
    ParametersMissing,
}

/// Read the current parameters from storage. Returns the parameters and gas
/// cost.
pub fn read<DB, H>(
    storage: &Storage<DB, H>,
) -> Result<(Parameters, u64), ReadError>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
{
    let key = storage_key();
    let (value, gas) = storage.read(&key).map_err(ReadError::StorageError)?;
    let parameters = decode(value.ok_or(ReadError::ParametersMissing)?)
        .map_err(ReadError::StorageTypeError)?;
    Ok((parameters, gas))
}

impl NativeVp for Parameters {
    const ADDR: InternalAddress = InternalAddress::Parameters;

    fn init_genesis_storage<DB, H>(_storage: &mut Storage<DB, H>)
    where
        DB: storage::DB + for<'iter> storage::DBIter<'iter>,
        H: storage::StorageHasher,
    {
        // TODO consider removing this from the trait, different VPs need
        // different args
    }

    fn validate_tx<DB, H>(
        _ctx: &mut super::native_vp::Ctx<DB, H>,
        _tx_data: &[u8],
        _keys_changed: &HashSet<Key>,
        _verifiers: &HashSet<Address>,
    ) -> vp_env::Result<bool>
    where
        DB: storage::DB + for<'iter> storage::DBIter<'iter>,
        H: storage::StorageHasher,
    {
        // TODO allow parameters change by over 2/3 validator voting power
        Ok(false)
    }
}

/// Storage key used for parameters.
fn storage_key() -> Key {
    Key {
        segments: vec![DbKeySeg::AddressSeg(Address::Internal(
            Parameters::ADDR,
        ))],
    }
}
