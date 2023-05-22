//! Protocol parameters
pub mod storage;

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use rust_decimal::Decimal;
use thiserror::Error;

use super::storage::types;
use super::storage_api::{self, ResultExt, StorageRead, StorageWrite};
use crate::ledger::storage as ledger_storage;
use crate::types::address::{Address, InternalAddress};
use crate::types::chain::ProposalBytes;
use crate::types::hash::Hash;
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
    /// Max gas for block
    pub max_block_gas: u64,
    /// Whitelisted validity predicate hashes (read only)
    pub vp_whitelist: Vec<String>,
    /// Whitelisted tx hashes (read only)
    pub tx_whitelist: Vec<String>,
    /// Implicit accounts validity predicate WASM code hash
    pub implicit_vp_code_hash: Hash,
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
    /// Gas table
    pub gas_table: BTreeMap<String, u64>,
    /// Fee unshielding gas limit
    pub fee_unshielding_gas_limit: u64,
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
    pub fn init_storage<S>(&self, storage: &mut S) -> storage_api::Result<()>
    where
        S: StorageRead + StorageWrite,
    {
        let Self {
            epoch_duration,
            max_expected_time_per_block,
            max_proposal_bytes,
            max_block_gas,
            vp_whitelist,
            tx_whitelist,
            implicit_vp_code_hash,
            epochs_per_year,
            pos_gain_p,
            pos_gain_d,
            staked_ratio,
            pos_inflation_amount,
            #[cfg(not(feature = "mainnet"))]
            faucet_account,
            #[cfg(not(feature = "mainnet"))]
            wrapper_tx_fees,
            gas_table,
            fee_unshielding_gas_limit,
        } = self;

        // write max proposal bytes parameter
        let max_proposal_bytes_key = storage::get_max_proposal_bytes_key();
        storage.write(&max_proposal_bytes_key, max_proposal_bytes)?;

        // write max block gas parameter
        let max_block_gas_key = storage::get_max_block_gas_key();
        storage.write(&max_block_gas_key, max_block_gas)?;

        // write epoch parameters
        let epoch_key = storage::get_epoch_duration_storage_key();
        storage.write(&epoch_key, epoch_duration)?;

        // write gas table
        let gas_table_key = storage::get_gas_table_storage_key();
        let gas_table = gas_table
            .iter()
            .map(|(k, v)| (k.to_lowercase(), *v))
            .collect::<BTreeMap<String, u64>>();
        storage.write(&gas_table_key, gas_table)?;

        // write fee unshielding gas limit
        let fee_unshielding_gas_limit_key =
            storage::get_fee_unshielding_gas_limit_key();
        storage
            .write(&fee_unshielding_gas_limit_key, fee_unshielding_gas_limit)?;

        // write vp whitelist parameter
        let vp_whitelist_key = storage::get_vp_whitelist_storage_key();
        let vp_whitelist = vp_whitelist
            .iter()
            .map(|id| id.to_lowercase())
            .collect::<Vec<String>>();
        storage.write(&vp_whitelist_key, vp_whitelist)?;

        // write tx whitelist parameter
        let tx_whitelist_key = storage::get_tx_whitelist_storage_key();
        let tx_whitelist = tx_whitelist
            .iter()
            .map(|id| id.to_lowercase())
            .collect::<Vec<String>>();
        storage.write(&tx_whitelist_key, tx_whitelist)?;

        // write max expected time per block
        let max_expected_time_per_block_key =
            storage::get_max_expected_time_per_block_key();
        storage.write(
            &max_expected_time_per_block_key,
            max_expected_time_per_block,
        )?;

        // write implicit vp parameter
        let implicit_vp_key = storage::get_implicit_vp_key();
        // Using `fn write_bytes` here, because implicit_vp code hash doesn't
        // need to be encoded, it's bytes already.
        storage.write_bytes(&implicit_vp_key, implicit_vp_code_hash)?;

        let epochs_per_year_key = storage::get_epochs_per_year_key();
        storage.write(&epochs_per_year_key, epochs_per_year)?;

        let pos_gain_p_key = storage::get_pos_gain_p_key();
        storage.write(&pos_gain_p_key, pos_gain_p)?;

        let pos_gain_d_key = storage::get_pos_gain_d_key();
        storage.write(&pos_gain_d_key, pos_gain_d)?;

        let staked_ratio_key = storage::get_staked_ratio_key();
        storage.write(&staked_ratio_key, staked_ratio)?;

        let pos_inflation_key = storage::get_pos_inflation_amount_key();
        storage.write(&pos_inflation_key, pos_inflation_amount)?;

        #[cfg(not(feature = "mainnet"))]
        if let Some(faucet_account) = faucet_account {
            let faucet_account_key = storage::get_faucet_account_key();
            storage.write(&faucet_account_key, faucet_account)?;
        }

        #[cfg(not(feature = "mainnet"))]
        {
            let wrapper_tx_fees_key = storage::get_wrapper_tx_fees_key();
            let wrapper_tx_fees =
                wrapper_tx_fees.unwrap_or(token::Amount::whole(100));
            storage.write(&wrapper_tx_fees_key, wrapper_tx_fees)?;
        }
        Ok(())
    }
}

/// Update the max_expected_time_per_block parameter in storage. Returns the
/// parameters and gas cost.
pub fn update_max_expected_time_per_block_parameter<S>(
    storage: &mut S,
    value: &DurationSecs,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_max_expected_time_per_block_key();
    storage.write(&key, value)
}

/// Update the vp whitelist parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_vp_whitelist_parameter<S>(
    storage: &mut S,
    value: Vec<String>,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_vp_whitelist_storage_key();
    storage.write(
        &key,
        value
            .iter()
            .map(|id| id.to_lowercase())
            .collect::<Vec<String>>(),
    )
}

/// Update the tx whitelist parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_tx_whitelist_parameter<S>(
    storage: &mut S,
    value: Vec<String>,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_tx_whitelist_storage_key();
    storage.write(
        &key,
        value
            .iter()
            .map(|id| id.to_lowercase())
            .collect::<Vec<String>>(),
    )
}

/// Update the epoch parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_epoch_parameter<S>(
    storage: &mut S,
    value: &EpochDuration,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_epoch_duration_storage_key();
    storage.write(&key, value)
}

/// Update the epochs_per_year parameter in storage. Returns the parameters and
/// gas cost.
pub fn update_epochs_per_year_parameter<S>(
    storage: &mut S,
    value: &u64,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_epochs_per_year_key();
    storage.write(&key, value)
}

/// Update the PoS P-gain parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_pos_gain_p_parameter<S>(
    storage: &mut S,
    value: &Decimal,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_pos_gain_p_key();
    storage.write(&key, value)
}

/// Update the PoS D-gain parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_pos_gain_d_parameter<S>(
    storage: &mut S,
    value: &Decimal,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_pos_gain_d_key();
    storage.write(&key, value)
}

/// Update the PoS staked ratio parameter in storage. Returns the parameters and
/// gas cost.
pub fn update_staked_ratio_parameter<S>(
    storage: &mut S,
    value: &Decimal,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_staked_ratio_key();
    storage.write(&key, value)
}

/// Update the PoS inflation rate parameter in storage. Returns the parameters
/// and gas cost.
pub fn update_pos_inflation_amount_parameter<S>(
    storage: &mut S,
    value: &u64,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_pos_inflation_amount_key();
    storage.write(&key, value)
}

/// Update the implicit VP parameter in storage. Return the gas cost.
pub fn update_implicit_vp<S>(
    storage: &mut S,
    implicit_vp: &[u8],
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_implicit_vp_key();
    // Using `fn write_bytes` here, because implicit_vp doesn't need to be
    // encoded, it's bytes already.
    storage.write_bytes(&key, implicit_vp)
}

/// Read the the epoch duration parameter from store
pub fn read_epoch_duration_parameter<S>(
    storage: &S,
) -> storage_api::Result<EpochDuration>
where
    S: StorageRead,
{
    // read epoch
    let epoch_key = storage::get_epoch_duration_storage_key();
    let epoch_duration = storage.read(&epoch_key)?;
    epoch_duration
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()
}

#[cfg(not(feature = "mainnet"))]
/// Read the faucet account's address, if any
pub fn read_faucet_account_parameter<S>(
    storage: &S,
) -> storage_api::Result<Option<Address>>
where
    S: StorageRead,
{
    let faucet_account_key = storage::get_faucet_account_key();
    storage.read(&faucet_account_key)
}

#[cfg(not(feature = "mainnet"))]
/// Read the wrapper tx fees amount, if any
pub fn read_wrapper_tx_fees_parameter<S>(
    storage: &S,
) -> storage_api::Result<Option<token::Amount>>
where
    S: StorageRead,
{
    let wrapper_tx_fees_key = storage::get_wrapper_tx_fees_key();
    storage.read(&wrapper_tx_fees_key)
}

// Read the all the parameters from storage. Returns the parameters and gas
/// cost.
pub fn read<S>(storage: &S) -> storage_api::Result<Parameters>
where
    S: StorageRead,
{
    // read max proposal bytes
    let max_proposal_bytes: ProposalBytes = {
        let key = storage::get_max_proposal_bytes_key();
        let value = storage.read(&key)?;
        value
            .ok_or(ReadError::ParametersMissing)
            .into_storage_result()?
    };

    // read max block gas
    let max_block_gas: u64 = {
        let key = storage::get_max_block_gas_key();
        let value = storage.read(&key)?;
        value
            .ok_or(ReadError::ParametersMissing)
            .into_storage_result()?
    };

    // read epoch duration
    let epoch_duration = read_epoch_duration_parameter(storage)?;

    // read vp whitelist
    let vp_whitelist_key = storage::get_vp_whitelist_storage_key();
    let value = storage.read(&vp_whitelist_key)?;
    let vp_whitelist: Vec<String> = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read tx whitelist
    let tx_whitelist_key = storage::get_tx_whitelist_storage_key();
    let value = storage.read(&tx_whitelist_key)?;
    let tx_whitelist: Vec<String> = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read max expected block time
    let max_expected_time_per_block_key =
        storage::get_max_expected_time_per_block_key();
    let value = storage.read(&max_expected_time_per_block_key)?;
    let max_expected_time_per_block: DurationSecs = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    let implicit_vp_key = storage::get_implicit_vp_key();
    let value = storage
        .read_bytes(&implicit_vp_key)?
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;
    let implicit_vp_code_hash =
        Hash::try_from(&value[..]).into_storage_result()?;

    // read gas table
    let gas_table_key = storage::get_gas_table_storage_key();
    let value = storage.read(&gas_table_key)?;
    let gas_table: BTreeMap<String, u64> = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read fee unshielding gas limit
    let fee_unshielding_gas_limit_key =
        storage::get_fee_unshielding_gas_limit_key();
    let value = storage.read(&fee_unshielding_gas_limit_key)?;
    let fee_unshielding_gas_limit: u64 = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read epochs per year
    let epochs_per_year_key = storage::get_epochs_per_year_key();
    let value = storage.read(&epochs_per_year_key)?;
    let epochs_per_year: u64 = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read PoS gain P
    let pos_gain_p_key = storage::get_pos_gain_p_key();
    let value = storage.read(&pos_gain_p_key)?;
    let pos_gain_p: Decimal = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read PoS gain D
    let pos_gain_d_key = storage::get_pos_gain_d_key();
    let value = storage.read(&pos_gain_d_key)?;
    let pos_gain_d: Decimal = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read staked ratio
    let staked_ratio_key = storage::get_staked_ratio_key();
    let value = storage.read(&staked_ratio_key)?;
    let staked_ratio: Decimal = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read PoS inflation rate
    let pos_inflation_key = storage::get_pos_inflation_amount_key();
    let value = storage.read(&pos_inflation_key)?;
    let pos_inflation_amount: u64 = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read faucet account
    #[cfg(not(feature = "mainnet"))]
    let faucet_account = read_faucet_account_parameter(storage)?;

    // read faucet account
    #[cfg(not(feature = "mainnet"))]
    let wrapper_tx_fees = read_wrapper_tx_fees_parameter(storage)?;

    Ok(Parameters {
        epoch_duration,
        max_expected_time_per_block,
        max_proposal_bytes,
        max_block_gas,
        vp_whitelist,
        tx_whitelist,
        implicit_vp_code_hash,
        epochs_per_year,
        pos_gain_p,
        pos_gain_d,
        staked_ratio,
        pos_inflation_amount,
        #[cfg(not(feature = "mainnet"))]
        faucet_account,
        #[cfg(not(feature = "mainnet"))]
        wrapper_tx_fees,
        gas_table,
        fee_unshielding_gas_limit,
    })
}
