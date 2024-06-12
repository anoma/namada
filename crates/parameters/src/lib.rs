//! Protocol parameters

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

pub mod storage;
mod wasm_allowlist;
use std::collections::BTreeMap;

use namada_core::address::{Address, InternalAddress};
use namada_core::chain::ProposalBytes;
pub use namada_core::parameters::*;
use namada_core::storage::Key;
use namada_core::time::DurationSecs;
use namada_core::token;
use namada_storage::{ResultExt, StorageRead, StorageWrite};
pub use storage::get_max_block_gas;
use thiserror::Error;
pub use wasm_allowlist::{is_tx_allowed, is_vp_allowed};

/// The internal address for storage keys representing parameters than
/// can be changed via governance.
pub const ADDRESS: Address = Address::Internal(InternalAddress::Parameters);

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ReadError {
    #[error("Storage error: {0}")]
    StorageError(namada_storage::Error),
    #[error("Storage type error: {0}")]
    StorageTypeError(namada_core::storage::Error),
    #[error("Protocol parameters are missing, they must be always set")]
    ParametersMissing,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum WriteError {
    #[error("Storage error: {0}")]
    StorageError(namada_storage::Error),
    #[error("Serialize error: {0}")]
    SerializeError(String),
}

/// Initialize parameters in storage in the genesis block.
pub fn init_storage<S>(
    parameters: &Parameters,
    storage: &mut S,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let Parameters {
        max_tx_bytes,
        epoch_duration,
        max_expected_time_per_block,
        max_proposal_bytes,
        max_block_gas,
        vp_allowlist,
        tx_allowlist,
        implicit_vp_code_hash,
        epochs_per_year,
        masp_epoch_multiplier,
        minimum_gas_price,
        fee_unshielding_gas_limit,
        is_native_token_transferable,
    } = parameters;

    // write max tx bytes parameter
    let max_tx_bytes_key = storage::get_max_tx_bytes_key();
    storage.write(&max_tx_bytes_key, max_tx_bytes)?;

    // write max proposal bytes parameter
    let max_proposal_bytes_key = storage::get_max_proposal_bytes_key();
    storage.write(&max_proposal_bytes_key, max_proposal_bytes)?;

    // write max block gas parameter
    let max_block_gas_key = storage::get_max_block_gas_key();
    storage.write(&max_block_gas_key, max_block_gas)?;

    // write epoch parameters
    let epoch_key = storage::get_epoch_duration_storage_key();
    storage.write(&epoch_key, epoch_duration)?;

    // write fee unshielding gas limit
    let fee_unshielding_gas_limit_key =
        storage::get_fee_unshielding_gas_limit_key();
    storage.write(&fee_unshielding_gas_limit_key, fee_unshielding_gas_limit)?;

    // write vp allowlist parameter
    let vp_allowlist_key = storage::get_vp_allowlist_storage_key();
    let vp_allowlist = vp_allowlist
        .iter()
        .map(|id| id.to_lowercase())
        .collect::<Vec<String>>();
    storage.write(&vp_allowlist_key, vp_allowlist)?;

    // write tx allowlist parameter
    let tx_allowlist_key = storage::get_tx_allowlist_storage_key();
    let tx_allowlist = tx_allowlist
        .iter()
        .map(|id| id.to_lowercase())
        .collect::<Vec<String>>();
    storage.write(&tx_allowlist_key, tx_allowlist)?;

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
    storage
        .write(&implicit_vp_key, implicit_vp_code_hash.unwrap_or_default())?;

    let epochs_per_year_key = storage::get_epochs_per_year_key();
    storage.write(&epochs_per_year_key, epochs_per_year)?;

    let masp_epoch_multiplier_key = storage::get_masp_epoch_multiplier_key();
    storage.write(&masp_epoch_multiplier_key, masp_epoch_multiplier)?;

    let gas_cost_key = storage::get_gas_cost_key();
    storage.write(&gas_cost_key, minimum_gas_price)?;

    let native_token_transferable_key =
        storage::get_native_token_transferable_key();
    storage
        .write(&native_token_transferable_key, is_native_token_transferable)?;

    Ok(())
}

/// Update the max_expected_time_per_block parameter in storage. Returns the
/// parameters and gas cost.
pub fn update_max_expected_time_per_block_parameter<S>(
    storage: &mut S,
    value: &DurationSecs,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_max_expected_time_per_block_key();
    storage.write(&key, value)
}

/// Update the vp allowlist parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_vp_allowlist_parameter<S>(
    storage: &mut S,
    value: Vec<String>,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_vp_allowlist_storage_key();
    storage.write(
        &key,
        value
            .iter()
            .map(|id| id.to_lowercase())
            .collect::<Vec<String>>(),
    )
}

/// Update the tx allowlist parameter in storage. Returns the parameters and gas
/// cost.
pub fn update_tx_allowlist_parameter<S>(
    storage: &mut S,
    value: Vec<String>,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_tx_allowlist_storage_key();
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
) -> namada_storage::Result<()>
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
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_epochs_per_year_key();
    storage.write(&key, value)
}

/// Update the implicit VP parameter in storage. Return the gas cost.
pub fn update_implicit_vp<S>(
    storage: &mut S,
    implicit_vp: &[u8],
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage::get_implicit_vp_key();
    // Using `fn write_bytes` here, because implicit_vp doesn't need to be
    // encoded, it's bytes already.
    storage.write(&key, implicit_vp)
}

/// Read the the epoch duration parameter from store
pub fn read_epoch_duration_parameter<S>(
    storage: &S,
) -> namada_storage::Result<EpochDuration>
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

/// Read the the masp epoch multiplier parameter from store
pub fn read_masp_epoch_multiplier_parameter<S>(
    storage: &S,
) -> namada_storage::Result<u64>
where
    S: StorageRead,
{
    // read multiplier
    let masp_epoch_multiplier_key = storage::get_masp_epoch_multiplier_key();
    let epoch_multiplier = storage.read(&masp_epoch_multiplier_key)?;
    epoch_multiplier
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()
}

/// Read the cost per unit of gas for the provided token
pub fn read_gas_cost<S>(
    storage: &S,
    token: &Address,
) -> namada_storage::Result<Option<token::Amount>>
where
    S: StorageRead,
{
    let gas_cost_table: BTreeMap<Address, token::Amount> = storage
        .read(&storage::get_gas_cost_key())?
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;
    Ok(gas_cost_table.get(token).map(|amount| amount.to_owned()))
}

/// Read all the parameters from storage. Returns the parameters and gas
/// cost.
pub fn read<S>(storage: &S) -> namada_storage::Result<Parameters>
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

    // read vp allowlist
    let vp_allowlist_key = storage::get_vp_allowlist_storage_key();
    let value = storage.read(&vp_allowlist_key)?;
    let vp_allowlist: Vec<String> = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read tx allowlist
    let tx_allowlist_key = storage::get_tx_allowlist_storage_key();
    let value = storage.read(&tx_allowlist_key)?;
    let tx_allowlist: Vec<String> = value
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
    let implicit_vp_code_hash = storage
        .read(&implicit_vp_key)?
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

    // read masp epoch multiplier
    let masp_epoch_multiplier = read_masp_epoch_multiplier_parameter(storage)?;

    // read gas cost
    let gas_cost_key = storage::get_gas_cost_key();
    let value = storage.read(&gas_cost_key)?;
    let minimum_gas_price: BTreeMap<Address, token::Amount> = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    // read max tx bytes
    let max_tx_bytes_key = storage::get_max_tx_bytes_key();
    let value = storage.read(&max_tx_bytes_key)?;
    let max_tx_bytes = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    let native_token_transferable_key =
        storage::get_native_token_transferable_key();
    let value = storage.read(&native_token_transferable_key)?;
    let is_native_token_transferable = value
        .ok_or(ReadError::ParametersMissing)
        .into_storage_result()?;

    Ok(Parameters {
        max_tx_bytes,
        epoch_duration,
        max_expected_time_per_block,
        max_proposal_bytes,
        max_block_gas,
        vp_allowlist,
        tx_allowlist,
        implicit_vp_code_hash: Some(implicit_vp_code_hash),
        epochs_per_year,
        masp_epoch_multiplier,
        minimum_gas_price,
        fee_unshielding_gas_limit,
        is_native_token_transferable,
    })
}

/// Validate the size of a tx.
pub fn validate_tx_bytes<S>(
    storage: &S,
    tx_size: usize,
) -> namada_storage::Result<bool>
where
    S: StorageRead,
{
    let max_tx_bytes: u32 = storage
        .read(&storage::get_max_tx_bytes_key())?
        .expect("The max tx bytes param should be present in storage");
    Ok(tx_size <= max_tx_bytes as usize)
}

/// Storage key for the Ethereum address of wNam.
pub fn native_erc20_key() -> Key {
    storage::get_native_erc20_key_at_addr(ADDRESS)
}

/// Initialize parameters to the storage for testing
#[cfg(any(test, feature = "testing"))]
pub fn init_test_storage<S>(storage: &mut S) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let params = Parameters {
        max_tx_bytes: 1024 * 1024,
        epoch_duration: EpochDuration {
            min_num_of_blocks: 1,
            min_duration: DurationSecs(3600),
        },
        max_expected_time_per_block: DurationSecs(3600),
        max_proposal_bytes: Default::default(),
        max_block_gas: 100,
        vp_allowlist: vec![],
        tx_allowlist: vec![],
        implicit_vp_code_hash: Default::default(),
        epochs_per_year: 365,
        masp_epoch_multiplier: 2,
        fee_unshielding_gas_limit: 0,
        minimum_gas_price: Default::default(),
        is_native_token_transferable: true,
    };
    init_storage(&params, storage)
}
