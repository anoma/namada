//! Protocol parameters
pub mod storage;

use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use rust_decimal::Decimal;
use thiserror::Error;

use self::storage as parameter_storage;
use super::governance::storage as gov_storage;
use super::storage::types::{decode, encode};
use super::storage::{types, Storage};
use crate::ledger::native_vp::{self, Ctx, NativeVp};
use crate::ledger::storage::{self as ledger_storage, StorageHasher};
use crate::ledger::vp_env::VpEnv;
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::Key;
use crate::types::time::DurationSecs;
use crate::vm::WasmCacheAccess;

const ADDRESS: Address = Address::Internal(InternalAddress::Parameters);

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(native_vp::Error),
}

/// Parameters functions result
pub type Result<T> = std::result::Result<T, Error>;

/// Parameters VP
pub struct ParametersVp<'a, DB, H, CA>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

impl<'a, DB, H, CA> NativeVp for ParametersVp<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = InternalAddress::Parameters;

    fn validate_tx(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let result = keys_changed.iter().all(|key| {
            let key_type: KeyType = key.into();
            match key_type {
                KeyType::PARAMETER => {
                    let proposal_id = u64::try_from_slice(tx_data).ok();
                    match proposal_id {
                        Some(id) => {
                            let proposal_execution_key =
                                gov_storage::get_proposal_execution_key(id);
                            self.ctx
                                .has_key_pre(&proposal_execution_key)
                                .unwrap_or(false)
                        }
                        _ => false,
                    }
                }
                KeyType::UNKNOWN_PARAMETER => false,
                KeyType::UNKNOWN => true,
            }
        });
        Ok(result)
    }
}

impl From<native_vp::Error> for Error {
    fn from(err: native_vp::Error) -> Self {
        Self::NativeVpError(err)
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ReadError {
    #[error("Storage error: {0}")]
    StorageError(ledger_storage::Error),
    #[error("Storage type error: {0}")]
    StorageTypeError(types::Error),
    #[error("Protocol parameters are missing, they must be always set")]
    ParametersMissing,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum WriteError {
    #[error("Storage error: {0}")]
    StorageError(ledger_storage::Error),
    #[error("Serialize error: {0}")]
    SerializeError(String),
}

/// Protocol parameters
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct Parameters {
    /// Epoch duration (read only)
    pub epoch_duration: EpochDuration,
    /// Maximum expected time per block (read only)
    pub max_expected_time_per_block: DurationSecs,
    /// Whitelisted validity predicate hashes (read only)
    pub vp_whitelist: Vec<String>,
    /// Whitelisted tx hashes (read only)
    pub tx_whitelist: Vec<String>,
    /// Expected number of epochs per year (read only)
    pub epochs_per_year: u64,
    /// PoS gain p (read only)
    pub pos_gain_p: Decimal,
    /// PoS gain d (read only)
    pub pos_gain_d: Decimal,
    /// PoS staked ratio (read + write for every epoch)
    pub staked_ratio: Decimal,
    /// PoS inflation amount from the last epoch (read + write for every epoch)
    pub pos_inflation_amount: u64,
}

/// Epoch duration. A new epoch begins as soon as both the `min_num_of_blocks`
/// and `min_duration` have passed since the beginning of the current epoch.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct EpochDuration {
    /// Minimum number of blocks in an epoch
    pub min_num_of_blocks: u64,
    /// Minimum duration of an epoch
    pub min_duration: DurationSecs,
}

impl Parameters {
    /// Initialize parameters in storage in the genesis block.
    pub fn init_storage<DB, H>(&self, storage: &mut Storage<DB, H>)
    where
        DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
        H: ledger_storage::StorageHasher,
    {
        // write epoch parameters
        let epoch_key = storage::get_epoch_duration_storage_key();
        let epoch_value = encode(&self.epoch_duration);
        storage.write(&epoch_key, epoch_value).expect(
            "Epoch parameters must be initialized in the genesis block",
        );

        // write vp whitelist parameter
        let vp_whitelist_key = storage::get_vp_whitelist_storage_key();
        let vp_whitelist_value = encode(&self.vp_whitelist);
        storage.write(&vp_whitelist_key, vp_whitelist_value).expect(
            "Vp whitelist parameters must be initialized in the genesis block",
        );

        // write tx whitelist parameter
        let tx_whitelist_key = storage::get_tx_whitelist_storage_key();
        let tx_whitelist_value = encode(&self.tx_whitelist);
        storage.write(&tx_whitelist_key, tx_whitelist_value).expect(
            "Tx whitelist parameters must be initialized in the genesis block",
        );

        // write tx whitelist parameter
        let max_expected_time_per_block_key =
            storage::get_max_expected_time_per_block_key();
        let max_expected_time_per_block_value =
            encode(&self.max_expected_time_per_block);
        storage
            .write(
                &max_expected_time_per_block_key,
                max_expected_time_per_block_value,
            )
            .expect(
                "Max expected time per block parameters must be initialized \
                 in the genesis block",
            );

        let epochs_per_year_key = storage::get_epochs_per_year_key();
        let epochs_per_year_value = encode(&self.epochs_per_year);
        storage
            .write(&epochs_per_year_key, epochs_per_year_value)
            .expect(
                "Epochs per year parameter must be initialized in the genesis \
                 block",
            );

        let pos_gain_p_key = storage::get_pos_gain_p_key();
        let pos_gain_p_value = encode(&self.pos_gain_p);
        storage.write(&pos_gain_p_key, pos_gain_p_value).expect(
            "PoS P-gain parameter must be initialized in the genesis block",
        );

        let pos_gain_d_key = storage::get_pos_gain_d_key();
        let pos_gain_d_value = encode(&self.pos_gain_d);
        storage.write(&pos_gain_d_key, pos_gain_d_value).expect(
            "PoS D-gain parameter must be initialized in the genesis block",
        );

        let staked_ratio_key = storage::get_staked_ratio_key();
        let staked_ratio_val = encode(&self.staked_ratio);
        storage.write(&staked_ratio_key, staked_ratio_val).expect(
            "PoS staked ratio parameter must be initialized in the genesis \
             block",
        );

        let pos_inflation_key = storage::get_pos_inflation_amount_key();
        let pos_inflation_val = encode(&self.pos_inflation_amount);
        storage.write(&pos_inflation_key, pos_inflation_val).expect(
            "PoS inflation rate parameter must be initialized in the genesis \
             block",
        );
    }
}

/// Update the max_expected_time_per_block parameter in storage. Returns the
/// parameters and gas cost.
pub fn update_max_expected_time_per_block_parameter<DB, H>(
    storage: &mut Storage<DB, H>,
    value: &DurationSecs,
) -> std::result::Result<u64, WriteError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    let key = storage::get_max_expected_time_per_block_key();
    update(storage, value, key)
}

/// Update the vp whitelist parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_vp_whitelist_parameter<DB, H>(
    storage: &mut Storage<DB, H>,
    value: Vec<String>,
) -> std::result::Result<u64, WriteError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    let key = storage::get_vp_whitelist_storage_key();
    update(storage, &value, key)
}

/// Update the tx whitelist parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_tx_whitelist_parameter<DB, H>(
    storage: &mut Storage<DB, H>,
    value: Vec<String>,
) -> std::result::Result<u64, WriteError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    let key = storage::get_tx_whitelist_storage_key();
    update(storage, &value, key)
}

/// Update the epoch parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_epoch_parameter<DB, H>(
    storage: &mut Storage<DB, H>,
    value: &EpochDuration,
) -> std::result::Result<u64, WriteError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    let key = storage::get_epoch_duration_storage_key();
    update(storage, value, key)
}

/// Update the epochs_per_year parameter in storage. Returns the parameters and
/// gas cost.
pub fn update_epochs_per_year_parameter<DB, H>(
    storage: &mut Storage<DB, H>,
    value: &EpochDuration,
) -> std::result::Result<u64, WriteError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    let key = storage::get_epochs_per_year_key();
    update(storage, value, key)
}

/// Update the PoS P-gain parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_pos_gain_p_parameter<DB, H>(
    storage: &mut Storage<DB, H>,
    value: &EpochDuration,
) -> std::result::Result<u64, WriteError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    let key = storage::get_pos_gain_p_key();
    update(storage, value, key)
}

/// Update the PoS D-gain parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_pos_gain_d_parameter<DB, H>(
    storage: &mut Storage<DB, H>,
    value: &EpochDuration,
) -> std::result::Result<u64, WriteError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    let key = storage::get_pos_gain_d_key();
    update(storage, value, key)
}

/// Update the PoS staked ratio parameter in storage. Returns the parameters and
/// gas cost.
pub fn update_staked_ratio_parameter<DB, H>(
    storage: &mut Storage<DB, H>,
    value: &EpochDuration,
) -> std::result::Result<u64, WriteError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    let key = storage::get_staked_ratio_key();
    update(storage, value, key)
}

/// Update the PoS inflation rate parameter in storage. Returns the parameters
/// and gas cost.
pub fn update_pos_inflation_amount_parameter<DB, H>(
    storage: &mut Storage<DB, H>,
    value: &EpochDuration,
) -> std::result::Result<u64, WriteError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    let key = storage::get_pos_inflation_amount_key();
    update(storage, value, key)
}

/// Update the  parameters in storage. Returns the parameters and gas
/// cost.
pub fn update<DB, H, T>(
    storage: &mut Storage<DB, H>,
    value: &T,
    key: Key,
) -> std::result::Result<u64, WriteError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
    T: BorshSerialize,
{
    let serialized_value = value
        .try_to_vec()
        .map_err(|e| WriteError::SerializeError(e.to_string()))?;
    let (gas, _size_diff) = storage
        .write(&key, serialized_value)
        .map_err(WriteError::StorageError)?;
    Ok(gas)
}

/// Read the the epoch duration parameter from store
pub fn read_epoch_duration_parameter<DB, H>(
    storage: &Storage<DB, H>,
) -> std::result::Result<(EpochDuration, u64), ReadError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    // read epoch
    let epoch_key = storage::get_epoch_duration_storage_key();
    let (value, gas) =
        storage.read(&epoch_key).map_err(ReadError::StorageError)?;
    let epoch_duration: EpochDuration =
        decode(value.ok_or(ReadError::ParametersMissing)?)
            .map_err(ReadError::StorageTypeError)?;

    Ok((epoch_duration, gas))
}

// Read the all the parameters from storage. Returns the parameters and gas
/// cost.
pub fn read<DB, H>(
    storage: &Storage<DB, H>,
) -> std::result::Result<(Parameters, u64), ReadError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    // read epoch duration
    let (epoch_duration, gas_epoch) = read_epoch_duration_parameter(storage)
        .expect("Couldn't read epoch duration parameters");

    // read vp whitelist
    let vp_whitelist_key = storage::get_vp_whitelist_storage_key();
    let (value, gas_vp) = storage
        .read(&vp_whitelist_key)
        .map_err(ReadError::StorageError)?;
    let vp_whitelist: Vec<String> =
        decode(value.ok_or(ReadError::ParametersMissing)?)
            .map_err(ReadError::StorageTypeError)?;

    // read tx whitelist
    let tx_whitelist_key = storage::get_tx_whitelist_storage_key();
    let (value, gas_tx) = storage
        .read(&tx_whitelist_key)
        .map_err(ReadError::StorageError)?;
    let tx_whitelist: Vec<String> =
        decode(value.ok_or(ReadError::ParametersMissing)?)
            .map_err(ReadError::StorageTypeError)?;

    let max_expected_time_per_block_key =
        storage::get_max_expected_time_per_block_key();
    let (value, gas_time) = storage
        .read(&max_expected_time_per_block_key)
        .map_err(ReadError::StorageError)?;
    let max_expected_time_per_block: DurationSecs =
        decode(value.ok_or(ReadError::ParametersMissing)?)
            .map_err(ReadError::StorageTypeError)?;

    // read epochs per year
    let epochs_per_year_key = storage::get_epochs_per_year_key();
    let (value, gas_epy) = storage
        .read(&epochs_per_year_key)
        .map_err(ReadError::StorageError)?;
    let epochs_per_year: u64 =
        decode(value.ok_or(ReadError::ParametersMissing)?)
            .map_err(ReadError::StorageTypeError)?;

    // read PoS gain P
    let pos_gain_p_key = storage::get_pos_gain_p_key();
    let (value, gas_gain_p) = storage
        .read(&pos_gain_p_key)
        .map_err(ReadError::StorageError)?;
    let pos_gain_p: Decimal =
        decode(value.ok_or(ReadError::ParametersMissing)?)
            .map_err(ReadError::StorageTypeError)?;

    // read PoS gain D
    let pos_gain_d_key = storage::get_pos_gain_d_key();
    let (value, gas_gain_d) = storage
        .read(&pos_gain_d_key)
        .map_err(ReadError::StorageError)?;
    let pos_gain_d: Decimal =
        decode(value.ok_or(ReadError::ParametersMissing)?)
            .map_err(ReadError::StorageTypeError)?;

    // read staked ratio
    let staked_ratio_key = storage::get_staked_ratio_key();
    let (value, gas_staked) = storage
        .read(&staked_ratio_key)
        .map_err(ReadError::StorageError)?;
    let staked_ratio: Decimal =
        decode(value.ok_or(ReadError::ParametersMissing)?)
            .map_err(ReadError::StorageTypeError)?;

    // read PoS inflation rate
    let pos_inflation_key = storage::get_pos_inflation_amount_key();
    let (value, gas_reward) = storage
        .read(&pos_inflation_key)
        .map_err(ReadError::StorageError)?;
    let pos_inflation_amount: u64 =
        decode(value.ok_or(ReadError::ParametersMissing)?)
            .map_err(ReadError::StorageTypeError)?;

    Ok((
        Parameters {
            epoch_duration,
            max_expected_time_per_block,
            vp_whitelist,
            tx_whitelist,
            epochs_per_year,
            pos_gain_p,
            pos_gain_d,
            staked_ratio,
            pos_inflation_amount,
        },
        gas_epoch
            + gas_tx
            + gas_vp
            + gas_time
            + gas_epy
            + gas_gain_p
            + gas_gain_d
            + gas_staked
            + gas_reward,
    ))
}

#[allow(clippy::upper_case_acronyms)]
enum KeyType {
    #[allow(clippy::upper_case_acronyms)]
    PARAMETER,
    #[allow(clippy::upper_case_acronyms)]
    #[allow(non_camel_case_types)]
    UNKNOWN_PARAMETER,
    #[allow(clippy::upper_case_acronyms)]
    UNKNOWN,
}

impl From<&Key> for KeyType {
    fn from(value: &Key) -> Self {
        if parameter_storage::is_protocol_parameter_key(value) {
            KeyType::PARAMETER
        } else if parameter_storage::is_parameter_key(value) {
            KeyType::UNKNOWN_PARAMETER
        } else {
            KeyType::UNKNOWN
        }
    }
}
