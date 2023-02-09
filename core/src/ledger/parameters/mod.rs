//! Protocol parameters
pub mod storage;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use rust_decimal::Decimal;
use thiserror::Error;

use super::storage::types::{decode, encode};
use super::storage::{types, Storage};
use crate::ledger::storage::{self as ledger_storage};
use crate::types::address::{Address, InternalAddress};
use crate::types::chain::ProposalBytes;
use crate::types::storage::Key;
use crate::types::time::DurationSecs;
use crate::types::token;

const ADDRESS: Address = Address::Internal(InternalAddress::Parameters);

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
    /// Max payload size, in bytes, for a tx batch proposal.
    pub max_proposal_bytes: ProposalBytes,
    /// Whitelisted validity predicate hashes (read only)
    pub vp_whitelist: Vec<String>,
    /// Whitelisted tx hashes (read only)
    pub tx_whitelist: Vec<String>,
    /// Implicit accounts validity predicate WASM code
    pub implicit_vp: Vec<u8>,
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
    #[cfg(not(feature = "mainnet"))]
    /// Faucet account for free token withdrawal
    pub faucet_account: Option<Address>,
    #[cfg(not(feature = "mainnet"))]
    /// Fixed fees for a wrapper tx to be accepted
    pub wrapper_tx_fees: Option<token::Amount>,
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

impl Parameters {
    /// Initialize parameters in storage in the genesis block.
    pub fn init_storage<DB, H>(&self, storage: &mut Storage<DB, H>)
    where
        DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
        H: ledger_storage::StorageHasher,
    {
        let Self {
            epoch_duration,
            max_expected_time_per_block,
            max_proposal_bytes,
            vp_whitelist,
            tx_whitelist,
            implicit_vp,
            epochs_per_year,
            pos_gain_p,
            pos_gain_d,
            staked_ratio,
            pos_inflation_amount,
            #[cfg(not(feature = "mainnet"))]
            faucet_account,
            #[cfg(not(feature = "mainnet"))]
            wrapper_tx_fees,
        } = self;

        // write max proposal bytes parameter
        let max_proposal_bytes_key = storage::get_max_proposal_bytes_key();
        let max_proposal_bytes_value = encode(&max_proposal_bytes);
        storage
            .write(&max_proposal_bytes_key, max_proposal_bytes_value)
            .expect(
                "Max proposal bytes parameter must be initialized in the \
                 genesis block",
            );

        // write epoch parameters
        let epoch_key = storage::get_epoch_duration_storage_key();
        let epoch_value = encode(epoch_duration);
        storage.write(&epoch_key, epoch_value).expect(
            "Epoch parameters must be initialized in the genesis block",
        );

        // write vp whitelist parameter
        let vp_whitelist_key = storage::get_vp_whitelist_storage_key();
        let vp_whitelist_value = encode(
            &vp_whitelist
                .iter()
                .map(|id| id.to_lowercase())
                .collect::<Vec<String>>(),
        );
        storage.write(&vp_whitelist_key, vp_whitelist_value).expect(
            "Vp whitelist parameter must be initialized in the genesis block",
        );

        // write tx whitelist parameter
        let tx_whitelist_key = storage::get_tx_whitelist_storage_key();
        let tx_whitelist_value = encode(
            &tx_whitelist
                .iter()
                .map(|id| id.to_lowercase())
                .collect::<Vec<String>>(),
        );
        storage.write(&tx_whitelist_key, tx_whitelist_value).expect(
            "Tx whitelist parameter must be initialized in the genesis block",
        );

        // write tx whitelist parameter
        let max_expected_time_per_block_key =
            storage::get_max_expected_time_per_block_key();
        let max_expected_time_per_block_value =
            encode(&max_expected_time_per_block);
        storage
            .write(
                &max_expected_time_per_block_key,
                max_expected_time_per_block_value,
            )
            .expect(
                "Max expected time per block parameter must be initialized in \
                 the genesis block",
            );

        // write implicit vp parameter
        let implicit_vp_key = storage::get_implicit_vp_key();
        storage.write(&implicit_vp_key, implicit_vp).expect(
            "Implicit VP parameter must be initialized in the genesis block",
        );

        let epochs_per_year_key = storage::get_epochs_per_year_key();
        let epochs_per_year_value = encode(epochs_per_year);
        storage
            .write(&epochs_per_year_key, epochs_per_year_value)
            .expect(
                "Epochs per year parameter must be initialized in the genesis \
                 block",
            );

        let pos_gain_p_key = storage::get_pos_gain_p_key();
        let pos_gain_p_value = encode(pos_gain_p);
        storage.write(&pos_gain_p_key, pos_gain_p_value).expect(
            "PoS P-gain parameter must be initialized in the genesis block",
        );

        let pos_gain_d_key = storage::get_pos_gain_d_key();
        let pos_gain_d_value = encode(pos_gain_d);
        storage.write(&pos_gain_d_key, pos_gain_d_value).expect(
            "PoS D-gain parameter must be initialized in the genesis block",
        );

        let staked_ratio_key = storage::get_staked_ratio_key();
        let staked_ratio_val = encode(staked_ratio);
        storage.write(&staked_ratio_key, staked_ratio_val).expect(
            "PoS staked ratio parameter must be initialized in the genesis \
             block",
        );

        let pos_inflation_key = storage::get_pos_inflation_amount_key();
        let pos_inflation_val = encode(pos_inflation_amount);
        storage.write(&pos_inflation_key, pos_inflation_val).expect(
            "PoS inflation rate parameter must be initialized in the genesis \
             block",
        );

        #[cfg(not(feature = "mainnet"))]
        if let Some(faucet_account) = faucet_account {
            let faucet_account_key = storage::get_faucet_account_key();
            let faucet_account_val = encode(faucet_account);
            storage
                .write(&faucet_account_key, faucet_account_val)
                .expect(
                    "Faucet account parameter must be initialized in the \
                     genesis block, if any",
                );
        }

        #[cfg(not(feature = "mainnet"))]
        {
            let wrapper_tx_fees_key = storage::get_wrapper_tx_fees_key();
            let wrapper_tx_fees_val =
                encode(&wrapper_tx_fees.unwrap_or(token::Amount::whole(100)));
            storage
                .write(&wrapper_tx_fees_key, wrapper_tx_fees_val)
                .expect(
                    "Wrapper tx fees must be initialized in the genesis block",
                );
        }
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
    update(
        storage,
        &value
            .iter()
            .map(|id| id.to_lowercase())
            .collect::<Vec<String>>(),
        key,
    )
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
    update(
        storage,
        &value
            .iter()
            .map(|id| id.to_lowercase())
            .collect::<Vec<String>>(),
        key,
    )
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

/// Update the implicit VP parameter in storage. Return the gas cost.
pub fn update_implicit_vp<DB, H>(
    storage: &mut Storage<DB, H>,
    implicit_vp: &[u8],
) -> std::result::Result<u64, WriteError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    let key = storage::get_implicit_vp_key();
    // Not using `fn update` here, because implicit_vp doesn't need to be
    // encoded, it's bytes already.
    let (gas, _size_diff) = storage
        .write(&key, implicit_vp)
        .map_err(WriteError::StorageError)?;
    Ok(gas)
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

#[cfg(not(feature = "mainnet"))]
/// Read the faucet account's address, if any
pub fn read_faucet_account_parameter<DB, H>(
    storage: &Storage<DB, H>,
) -> std::result::Result<(Option<Address>, u64), ReadError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    let faucet_account_key = storage::get_faucet_account_key();
    let (value, gas_faucet_account) = storage
        .read(&faucet_account_key)
        .map_err(ReadError::StorageError)?;
    let address: Option<Address> = value
        .map(|value| decode(value).map_err(ReadError::StorageTypeError))
        .transpose()?;
    Ok((address, gas_faucet_account))
}

#[cfg(not(feature = "mainnet"))]
/// Read the wrapper tx fees amount, if any
pub fn read_wrapper_tx_fees_parameter<DB, H>(
    storage: &Storage<DB, H>,
) -> std::result::Result<(Option<token::Amount>, u64), ReadError>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: ledger_storage::StorageHasher,
{
    let wrapper_tx_fees_key = storage::get_wrapper_tx_fees_key();
    let (value, gas_wrapper_tx_fees) = storage
        .read(&wrapper_tx_fees_key)
        .map_err(ReadError::StorageError)?;
    let fee: Option<token::Amount> = value
        .map(|value| decode(value).map_err(ReadError::StorageTypeError))
        .transpose()?;
    Ok((fee, gas_wrapper_tx_fees))
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
    // read max proposal bytes
    let (max_proposal_bytes, gas_proposal_bytes) = {
        let key = storage::get_max_proposal_bytes_key();
        let (value, gas) =
            storage.read(&key).map_err(ReadError::StorageError)?;
        let value: ProposalBytes =
            decode(value.ok_or(ReadError::ParametersMissing)?)
                .map_err(ReadError::StorageTypeError)?;
        (value, gas)
    };

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

    // read max expected block time
    let max_expected_time_per_block_key =
        storage::get_max_expected_time_per_block_key();
    let (value, gas_time) = storage
        .read(&max_expected_time_per_block_key)
        .map_err(ReadError::StorageError)?;
    let max_expected_time_per_block: DurationSecs =
        decode(value.ok_or(ReadError::ParametersMissing)?)
            .map_err(ReadError::StorageTypeError)?;

    let implicit_vp_key = storage::get_implicit_vp_key();
    let (value, gas_implicit_vp) = storage
        .read(&implicit_vp_key)
        .map_err(ReadError::StorageError)?;
    let implicit_vp = value.ok_or(ReadError::ParametersMissing)?;

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

    // read faucet account
    #[cfg(not(feature = "mainnet"))]
    let (faucet_account, gas_faucet_account) =
        read_faucet_account_parameter(storage)?;
    #[cfg(feature = "mainnet")]
    let gas_faucet_account = 0;

    // read faucet account
    #[cfg(not(feature = "mainnet"))]
    let (wrapper_tx_fees, gas_wrapper_tx_fees) =
        read_wrapper_tx_fees_parameter(storage)?;
    #[cfg(feature = "mainnet")]
    let gas_wrapper_tx_fees = 0;

    let total_gas_cost = [
        gas_epoch,
        gas_tx,
        gas_vp,
        gas_time,
        gas_implicit_vp,
        gas_epy,
        gas_gain_p,
        gas_gain_d,
        gas_staked,
        gas_reward,
        gas_proposal_bytes,
        gas_faucet_account,
        gas_wrapper_tx_fees,
    ]
    .into_iter()
    .fold(0u64, |accum, gas| {
        accum
            .checked_add(gas)
            .expect("u64 overflow occurred while doing gas arithmetic")
    });

    Ok((
        Parameters {
            epoch_duration,
            max_expected_time_per_block,
            max_proposal_bytes,
            vp_whitelist,
            tx_whitelist,
            implicit_vp,
            epochs_per_year,
            pos_gain_p,
            pos_gain_d,
            staked_ratio,
            pos_inflation_amount,
            #[cfg(not(feature = "mainnet"))]
            faucet_account,
            #[cfg(not(feature = "mainnet"))]
            wrapper_tx_fees,
        },
        total_gas_cost,
    ))
}
