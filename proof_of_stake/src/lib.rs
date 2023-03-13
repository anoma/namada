//! Proof of Stake system.
//!
//! TODO: We might need to storage both active and total validator set voting
//! power. For consensus, we only consider active validator set voting power,
//! but for other activities in which inactive validators can participate (e.g.
//! voting on a protocol parameter changes, upgrades, default VP changes) we
//! should use the total validator set voting power.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

pub mod btree_set;
pub mod epoched;
pub mod parameters;
pub mod storage;
pub mod types;
// pub mod validation;

#[cfg(test)]
mod tests;

use core::fmt::Debug;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::TryFromIntError;

use borsh::BorshDeserialize;
use epoched::{EpochOffset, OffsetPipelineLen};
use namada_core::ledger::storage_api::collections::lazy_map::{
    NestedSubKey, SubKey,
};
use namada_core::ledger::storage_api::collections::{LazyCollection, LazySet};
use namada_core::ledger::storage_api::token::credit_tokens;
use namada_core::ledger::storage_api::{
    self, OptionExt, StorageRead, StorageWrite,
};
use namada_core::types::address::{self, Address, InternalAddress};
use namada_core::types::key::{
    common, tm_consensus_key_raw_hash, PublicKeyTmRawHash,
};
pub use namada_core::types::storage::Epoch;
use namada_core::types::token;
use once_cell::unsync::Lazy;
use parameters::PosParams;
use rust_decimal::Decimal;
use storage::{
    bonds_for_source_prefix, bonds_prefix, consensus_keys_key,
    get_validator_address_from_bond, into_tm_voting_power, is_bond_key,
    is_unbond_key, is_validator_slashes_key, mult_amount,
    mult_change_to_amount, num_consensus_validators_key, params_key,
    slashes_prefix, unbonds_for_source_prefix, unbonds_prefix,
    validator_address_raw_hash_key, validator_max_commission_rate_change_key,
    BondDetails, BondsAndUnbondsDetail, BondsAndUnbondsDetails,
    ReverseOrdTokenAmount, UnbondDetails, WeightedValidator,
};
use thiserror::Error;
use types::{
    BelowCapacityValidatorSet, BelowCapacityValidatorSets, Bonds,
    CommissionRates, ConsensusValidator, ConsensusValidatorSet,
    ConsensusValidatorSets, GenesisValidator, Position, Slash, SlashType,
    Slashes, TotalDeltas, Unbonds, ValidatorConsensusKeys, ValidatorDeltas,
    ValidatorPositionAddresses, ValidatorSetPositions, ValidatorSetUpdate,
    ValidatorState, ValidatorStates,
};

use crate::types::{decimal_mult_i128, decimal_mult_u64, BondId};

/// Address of the PoS account implemented as a native VP
pub const ADDRESS: Address = Address::Internal(InternalAddress::PoS);

/// Address of the PoS slash pool account
pub const SLASH_POOL_ADDRESS: Address =
    Address::Internal(InternalAddress::PosSlashPool);

/// Address of the staking token (NAM)
pub fn staking_token_address() -> Address {
    address::nam()
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum GenesisError {
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum BecomeValidatorError {
    #[error("The given address {0} is already a validator")]
    AlreadyValidator(Address),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum BondError {
    #[error("The given address {0} is not a validator address")]
    NotAValidator(Address),
    #[error(
        "The given source address {0} is a validator address. Validators may \
         not delegate."
    )]
    SourceMustNotBeAValidator(Address),
    #[error("The given validator address {0} is inactive")]
    InactiveValidator(Address),
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum UnbondError {
    #[error("No bond could be found")]
    NoBondFound,
    #[error(
        "Trying to withdraw more tokens ({0}) than the amount bonded ({0})"
    )]
    UnbondAmountGreaterThanBond(token::Amount, token::Amount),
    #[error("No bonds found for the validator {0}")]
    ValidatorHasNoBonds(Address),
    #[error("Voting power not found for the validator {0}")]
    ValidatorHasNoVotingPower(Address),
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum WithdrawError {
    #[error("No unbond could be found for {0}")]
    NoUnbondFound(BondId),
    #[error("No unbond may be withdrawn yet for {0}")]
    NoWithdrawableUnbond(BondId),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum SlashError {
    #[error("The validator {0} has no total deltas value")]
    ValidatorHasNoTotalDeltas(Address),
    #[error("The validator {0} has no voting power")]
    ValidatorHasNoVotingPower(Address),
    #[error("Unexpected slash token change")]
    InvalidSlashChange(i128),
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
    #[error("Unexpected negative stake {0} for validator {1}")]
    NegativeStake(i128, Address),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum CommissionRateChangeError {
    #[error("Unexpected negative commission rate {0} for validator {1}")]
    NegativeRate(Decimal, Address),
    #[error("Rate change of {0} is too large for validator {1}")]
    RateChangeTooLarge(Decimal, Address),
    #[error(
        "There is no maximum rate change written in storage for validator {0}"
    )]
    NoMaxSetInStorage(Address),
    #[error("Cannot write to storage for validator {0}")]
    CannotWrite(Address),
    #[error("Cannot read storage for validator {0}")]
    CannotRead(Address),
}

// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------

impl From<BecomeValidatorError> for storage_api::Error {
    fn from(err: BecomeValidatorError) -> Self {
        Self::new(err)
    }
}

impl From<BondError> for storage_api::Error {
    fn from(err: BondError) -> Self {
        Self::new(err)
    }
}

impl From<UnbondError> for storage_api::Error {
    fn from(err: UnbondError) -> Self {
        Self::new(err)
    }
}

impl From<WithdrawError> for storage_api::Error {
    fn from(err: WithdrawError) -> Self {
        Self::new(err)
    }
}

impl From<CommissionRateChangeError> for storage_api::Error {
    fn from(err: CommissionRateChangeError) -> Self {
        Self::new(err)
    }
}

/// Get the storage handle to the epoched consensus validator set
pub fn consensus_validator_set_handle() -> ConsensusValidatorSets {
    let key = storage::consensus_validator_set_key();
    ConsensusValidatorSets::open(key)
}

/// Get the storage handle to the epoched below-capacity validator set
pub fn below_capacity_validator_set_handle() -> BelowCapacityValidatorSets {
    let key = storage::below_capacity_validator_set_key();
    BelowCapacityValidatorSets::open(key)
}

/// Get the storage handle to a PoS validator's consensus key (used for
/// signing block votes).
pub fn validator_consensus_key_handle(
    validator: &Address,
) -> ValidatorConsensusKeys {
    let key = storage::validator_consensus_key_key(validator);
    ValidatorConsensusKeys::open(key)
}

/// Get the storage handle to a PoS validator's state
pub fn validator_state_handle(validator: &Address) -> ValidatorStates {
    let key = storage::validator_state_key(validator);
    ValidatorStates::open(key)
}

/// Get the storage handle to a PoS validator's deltas
pub fn validator_deltas_handle(validator: &Address) -> ValidatorDeltas {
    let key = storage::validator_deltas_key(validator);
    ValidatorDeltas::open(key)
}

/// Get the storage handle to the total deltas
pub fn total_deltas_handle() -> TotalDeltas {
    let key = storage::total_deltas_key();
    TotalDeltas::open(key)
}

/// Get the storage handle to a PoS validator's commission rate
pub fn validator_commission_rate_handle(
    validator: &Address,
) -> CommissionRates {
    let key = storage::validator_commission_rate_key(validator);
    CommissionRates::open(key)
}

/// Get the storage handle to a bond
/// TODO: remove `get_remaining` and the unused storage (maybe just call it
/// `storage::bond_key`)
pub fn bond_handle(source: &Address, validator: &Address) -> Bonds {
    let bond_id = BondId {
        source: source.clone(),
        validator: validator.clone(),
    };
    let key = storage::bond_key(&bond_id);
    Bonds::open(key)
}

/// Get the storage handle to an unbond
pub fn unbond_handle(source: &Address, validator: &Address) -> Unbonds {
    let bond_id = BondId {
        source: source.clone(),
        validator: validator.clone(),
    };
    let key = storage::unbond_key(&bond_id);
    Unbonds::open(key)
}

/// Get the storage handle to a PoS validator's deltas
pub fn validator_set_positions_handle() -> ValidatorSetPositions {
    let key = storage::validator_set_positions_key();
    ValidatorSetPositions::open(key)
}

/// Get the storage handle to a PoS validator's slashes
pub fn validator_slashes_handle(validator: &Address) -> Slashes {
    let key = storage::validator_slashes_key(validator);
    Slashes::open(key)
}

/// Init genesis
pub fn init_genesis<S>(
    storage: &mut S,
    params: &PosParams,
    validators: impl Iterator<Item = GenesisValidator> + Clone,
    current_epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    tracing::debug!("Initializing PoS genesis");
    write_pos_params(storage, params.clone())?;

    let mut total_bonded = token::Amount::default();
    consensus_validator_set_handle().init(storage, current_epoch)?;
    below_capacity_validator_set_handle().init(storage, current_epoch)?;
    validator_set_positions_handle().init(storage, current_epoch)?;

    for GenesisValidator {
        address,
        tokens,
        consensus_key,
        commission_rate,
        max_commission_rate_change,
    } in validators
    {
        // This will fail if the key is already being used - the uniqueness must
        // be enforced in the genesis configuration to prevent it
        try_insert_consensus_key(storage, &consensus_key)?;

        total_bonded += tokens;

        // Insert the validator into a validator set and write its epoched
        // validator data
        insert_validator_into_validator_set(
            storage,
            params,
            &address,
            tokens,
            current_epoch,
            0,
        )?;

        // Write other validator data to storage
        write_validator_address_raw_hash(storage, &address, &consensus_key)?;
        write_validator_max_commission_rate_change(
            storage,
            &address,
            max_commission_rate_change,
        )?;
        validator_consensus_key_handle(&address).init_at_genesis(
            storage,
            consensus_key,
            current_epoch,
        )?;
        let delta = token::Change::from(tokens);
        validator_deltas_handle(&address).init_at_genesis(
            storage,
            delta,
            current_epoch,
        )?;
        bond_handle(&address, &address).init_at_genesis(
            storage,
            delta,
            current_epoch,
        )?;
        validator_commission_rate_handle(&address).init_at_genesis(
            storage,
            commission_rate,
            current_epoch,
        )?;
    }
    // Write total deltas to storage
    total_deltas_handle().init_at_genesis(
        storage,
        token::Change::from(total_bonded),
        current_epoch,
    )?;
    // Credit bonded token amount to the PoS account
    credit_tokens(storage, &staking_token_address(), &ADDRESS, total_bonded)?;
    // Copy the genesis validator set into the pipeline epoch as well
    for epoch in (current_epoch.next()).iter_range(params.pipeline_len) {
        copy_validator_sets_and_positions(
            storage,
            current_epoch,
            epoch,
            &consensus_validator_set_handle(),
            &below_capacity_validator_set_handle(),
        )?;
    }

    tracing::debug!("FINISHED GENESIS");

    Ok(())
}

/// Read PoS parameters
pub fn read_pos_params<S>(storage: &S) -> storage_api::Result<PosParams>
where
    S: StorageRead,
{
    storage
        .read(&params_key())
        .transpose()
        .expect("PosParams should always exist in storage after genesis")
}

/// Write PoS parameters
pub fn write_pos_params<S>(
    storage: &mut S,
    params: PosParams,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = params_key();
    storage.write(&key, params)
}

/// Get the validator address given the raw hash of the Tendermint consensus key
pub fn find_validator_by_raw_hash<S>(
    storage: &S,
    raw_hash: impl AsRef<str>,
) -> storage_api::Result<Option<Address>>
where
    S: StorageRead,
{
    let key = validator_address_raw_hash_key(raw_hash);
    storage.read(&key)
}

/// Write PoS validator's address raw hash.
pub fn write_validator_address_raw_hash<S>(
    storage: &mut S,
    validator: &Address,
    consensus_key: &common::PublicKey,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let raw_hash = tm_consensus_key_raw_hash(consensus_key);
    storage.write(&validator_address_raw_hash_key(raw_hash), validator)
}

/// Read PoS validator's max commission rate change.
pub fn read_validator_max_commission_rate_change<S>(
    storage: &S,
    validator: &Address,
) -> storage_api::Result<Option<Decimal>>
where
    S: StorageRead,
{
    let key = validator_max_commission_rate_change_key(validator);
    storage.read(&key)
}

/// Write PoS validator's max commission rate change.
pub fn write_validator_max_commission_rate_change<S>(
    storage: &mut S,
    validator: &Address,
    change: Decimal,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = validator_max_commission_rate_change_key(validator);
    storage.write(&key, change)
}

/// Read number of consensus PoS validators.
pub fn read_num_consensus_validators<S>(storage: &S) -> storage_api::Result<u64>
where
    S: StorageRead,
{
    Ok(storage
        .read(&num_consensus_validators_key())?
        .unwrap_or_default())
}

/// Read number of consensus PoS validators.
pub fn write_num_consensus_validators<S>(
    storage: &mut S,
    new_num: u64,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = num_consensus_validators_key();
    storage.write(&key, new_num)
}

/// Read PoS validator's delta value.
pub fn read_validator_delta_value<S>(
    storage: &S,
    params: &PosParams,
    validator: &Address,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<Option<token::Change>>
where
    S: StorageRead,
{
    let handle = validator_deltas_handle(validator);
    handle.get_delta_val(storage, epoch, params)
}

/// Read PoS validator's stake (sum of deltas).
/// Returns `None` when the given address is not a validator address. For a
/// validator with `0` stake, this returns `Ok(token::Amount::default())`.
pub fn read_validator_stake<S>(
    storage: &S,
    params: &PosParams,
    validator: &Address,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<Option<token::Amount>>
where
    S: StorageRead,
{
    tracing::debug!("Read validator stake at epoch {}", epoch);
    let handle = validator_deltas_handle(validator);
    let amount = handle
        .get_sum(storage, epoch, params)?
        .map(token::Amount::from_change);
    Ok(amount)
}

/// Add or remove PoS validator's stake delta value
pub fn update_validator_deltas<S>(
    storage: &mut S,
    params: &PosParams,
    validator: &Address,
    delta: token::Change,
    current_epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let handle = validator_deltas_handle(validator);
    let offset = OffsetPipelineLen::value(params);
    let val = handle
        .get_delta_val(storage, current_epoch + offset, params)?
        .unwrap_or_default();
    handle.set(storage, val + delta, current_epoch, offset)
}

/// Read PoS total stake (sum of deltas).
pub fn read_total_stake<S>(
    storage: &S,
    params: &PosParams,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    let handle = total_deltas_handle();
    let amnt = handle
        .get_sum(storage, epoch, params)?
        .map(token::Amount::from_change)
        .unwrap_or_default();
    Ok(amnt)
}

/// Read all addresses from consensus validator set.
pub fn read_consensus_validator_set_addresses<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<HashSet<Address>>
where
    S: StorageRead,
{
    consensus_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .map(|res| res.map(|(_sub_key, address)| address))
        .collect()
}

/// Read all addresses from below-capacity validator set.
pub fn read_below_capacity_validator_set_addresses<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<HashSet<Address>>
where
    S: StorageRead,
{
    below_capacity_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .map(|res| res.map(|(_sub_key, address)| address))
        .collect()
}

/// Read all addresses from consensus validator set with their stake.
pub fn read_consensus_validator_set_addresses_with_stake<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<HashSet<WeightedValidator>>
where
    S: StorageRead,
{
    consensus_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .map(|res| {
            res.map(
                |(
                    NestedSubKey::Data {
                        key: bonded_stake,
                        nested_sub_key: _,
                    },
                    address,
                )| {
                    WeightedValidator {
                        address,
                        bonded_stake,
                    }
                },
            )
        })
        .collect()
}

/// Read all addresses from below-capacity validator set with their stake.
pub fn read_below_capacity_validator_set_addresses_with_stake<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<HashSet<WeightedValidator>>
where
    S: StorageRead,
{
    below_capacity_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .map(|res| {
            res.map(
                |(
                    NestedSubKey::Data {
                        key: ReverseOrdTokenAmount(bonded_stake),
                        nested_sub_key: _,
                    },
                    address,
                )| {
                    WeightedValidator {
                        address,
                        bonded_stake,
                    }
                },
            )
        })
        .collect()
}

/// Read all validator addresses.
pub fn read_all_validator_addresses<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<HashSet<Address>>
where
    S: StorageRead,
{
    let mut addresses = read_consensus_validator_set_addresses(storage, epoch)?;
    let bc_addresses =
        read_below_capacity_validator_set_addresses(storage, epoch)?;
    addresses.extend(bc_addresses.into_iter());
    Ok(addresses)
}

/// Update PoS total deltas.
/// Note: for EpochedDelta, write the value to change storage by
pub fn update_total_deltas<S>(
    storage: &mut S,
    params: &PosParams,
    delta: token::Change,
    current_epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let handle = total_deltas_handle();
    let offset = OffsetPipelineLen::value(params);
    let val = handle
        .get_delta_val(storage, current_epoch + offset, params)?
        .unwrap_or_default();
    handle.set(storage, val + delta, current_epoch, offset)
}

/// Check if the provided address is a validator address
pub fn is_validator<S>(
    storage: &S,
    address: &Address,
    params: &PosParams,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<bool>
where
    S: StorageRead + StorageWrite,
{
    let state = validator_state_handle(address).get(storage, epoch, params)?;
    Ok(state.is_some())
}

/// Check if the provided address is a delegator address, optionally at a
/// particular epoch
pub fn is_delegator<S>(
    storage: &S,
    address: &Address,
    epoch: Option<namada_core::types::storage::Epoch>,
) -> storage_api::Result<bool>
where
    S: StorageRead + StorageWrite,
{
    let prefix = bonds_for_source_prefix(address);
    match epoch {
        Some(epoch) => {
            let iter = storage_api::iter_prefix_bytes(storage, &prefix)?;
            for res in iter {
                let (key, _) = res?;
                if let Some((bond_id, bond_epoch)) = is_bond_key(&key) {
                    if bond_id.source != bond_id.validator
                        && bond_epoch <= epoch
                    {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        None => Ok(storage_api::iter_prefix_bytes(storage, &prefix)?
            .next()
            .is_some()),
    }
}

/// Self-bond tokens to a validator when `source` is `None` or equal to
/// the `validator` address, or delegate tokens from the `source` to the
/// `validator`.
pub fn bond_tokens<S>(
    storage: &mut S,
    source: Option<&Address>,
    validator: &Address,
    amount: token::Amount,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let amount = amount.change();
    tracing::debug!("Bonding token amount {amount} at epoch {current_epoch}");
    let params = read_pos_params(storage)?;
    let pipeline_epoch = current_epoch + params.pipeline_len;
    if let Some(source) = source {
        if source != validator
            && is_validator(storage, source, &params, pipeline_epoch)?
        {
            return Err(
                BondError::SourceMustNotBeAValidator(source.clone()).into()
            );
        }
    }
    let state = validator_state_handle(validator).get(
        storage,
        pipeline_epoch,
        &params,
    )?;
    if state.is_none() {
        return Err(BondError::NotAValidator(validator.clone()).into());
    }

    let validator_state_handle = validator_state_handle(validator);
    let source = source.unwrap_or(validator);
    let bond_handle = bond_handle(source, validator);

    // Check that validator is not inactive at anywhere between the current
    // epoch and pipeline offset
    for epoch in current_epoch.iter_range(params.pipeline_len) {
        if let Some(ValidatorState::Inactive) =
            validator_state_handle.get(storage, epoch, &params)?
        {
            return Err(BondError::InactiveValidator(validator.clone()).into());
        }
    }

    // Initialize or update the bond at the pipeline offset
    let offset = params.pipeline_len;
    let cur_remain = bond_handle
        .get_delta_val(storage, current_epoch + offset, &params)?
        .unwrap_or_default();
    tracing::debug!(
        "Bond remain at offset epoch {}: {}",
        current_epoch + offset,
        cur_remain
    );
    bond_handle.set(storage, cur_remain + amount, current_epoch, offset)?;

    // Update the validator set
    update_validator_set(storage, &params, validator, amount, current_epoch)?;

    // Update the validator and total deltas
    update_validator_deltas(
        storage,
        &params,
        validator,
        amount,
        current_epoch,
    )?;

    update_total_deltas(storage, &params, amount, current_epoch)?;

    // Transfer the bonded tokens from the source to PoS
    transfer_tokens(
        storage,
        &staking_token_address(),
        token::Amount::from_change(amount),
        source,
        &ADDRESS,
    )?;

    Ok(())
}

/// Insert the new validator into the right validator set (depending on its
/// stake)
fn insert_validator_into_validator_set<S>(
    storage: &mut S,
    params: &PosParams,
    address: &Address,
    stake: token::Amount,
    current_epoch: Epoch,
    offset: u64,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let target_epoch = current_epoch + offset;
    let consensus_set = &consensus_validator_set_handle().at(&target_epoch);
    let below_cap_set =
        &below_capacity_validator_set_handle().at(&target_epoch);
    // TODO make epoched
    let num_consensus_validators = read_num_consensus_validators(storage)?;
    if num_consensus_validators < params.max_validator_slots {
        insert_validator_into_set(
            &consensus_set.at(&stake),
            storage,
            &target_epoch,
            address,
        )?;
        validator_state_handle(address).set(
            storage,
            ValidatorState::Consensus,
            current_epoch,
            offset,
        )?;
        write_num_consensus_validators(storage, num_consensus_validators + 1)?;
    } else {
        // Check to see if the current genesis validator should replace one
        // already in the consensus set
        let min_consensus_amount =
            get_min_consensus_validator_amount(consensus_set, storage)?;
        if stake > min_consensus_amount {
            // Swap this genesis validator in and demote the last min consensus
            // validator
            let min_consensus_handle = consensus_set.at(&min_consensus_amount);
            // Remove last min consensus validator
            let last_min_consensus_position =
                find_last_position(&min_consensus_handle, storage)?.expect(
                    "There must be always be at least 1 consensus validator",
                );
            let removed = min_consensus_handle
                .remove(storage, &last_min_consensus_position)?
                .expect(
                    "There must be always be at least 1 consensus validator",
                );
            // Insert last min consensus validator into the below-capacity set
            insert_validator_into_set(
                &below_cap_set.at(&min_consensus_amount.into()),
                storage,
                &target_epoch,
                &removed,
            )?;
            validator_state_handle(&removed).set(
                storage,
                ValidatorState::BelowCapacity,
                current_epoch,
                offset,
            )?;
            // Insert the current genesis validator into the consensus set
            insert_validator_into_set(
                &consensus_set.at(&stake),
                storage,
                &target_epoch,
                address,
            )?;
            validator_state_handle(address).set(
                storage,
                ValidatorState::Consensus,
                current_epoch,
                offset,
            )?;
            // Update and set the validator states
        } else {
            // Insert the current genesis validator into the below-capacity set
            insert_validator_into_set(
                &below_cap_set.at(&stake.into()),
                storage,
                &target_epoch,
                address,
            )?;
            validator_state_handle(address).set(
                storage,
                ValidatorState::BelowCapacity,
                current_epoch,
                offset,
            )?;
        }
    }
    Ok(())
}

/// Update validator set when a validator receives a new bond and when
/// its bond is unbonded (self-bond or delegation).
fn update_validator_set<S>(
    storage: &mut S,
    params: &PosParams,
    validator: &Address,
    token_change: token::Change,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    if token_change == 0_i128 {
        return Ok(());
    }
    let epoch = current_epoch + params.pipeline_len;
    tracing::debug!(
        "Update epoch for validator set: {epoch}, validator: {validator}"
    );
    let consensus_validator_set = consensus_validator_set_handle();
    let below_capacity_validator_set = below_capacity_validator_set_handle();

    // Validator sets at the pipeline offset. If these are empty, then we need
    // to copy over the most recent filled validator set into this epoch first
    let consensus_val_handle = consensus_validator_set.at(&epoch);
    let below_capacity_val_handle = below_capacity_validator_set.at(&epoch);

    let tokens_pre = read_validator_stake(storage, params, validator, epoch)?
        .unwrap_or_default();

    // tracing::debug!("VALIDATOR STAKE BEFORE UPDATE: {}", tokens_pre);

    let tokens_post = tokens_pre.change() + token_change;
    // TODO: handle overflow or negative vals perhaps with TryFrom
    let tokens_post = token::Amount::from_change(tokens_post);

    // TODO: The position is only set when the validator is in consensus or
    // below_capacity set (not in below_threshold set)
    let position =
        read_validator_set_position(storage, validator, epoch, params)?
            .ok_or_err_msg(
                "Validator must have a stored validator set position",
            )?;
    let consensus_vals_pre = consensus_val_handle.at(&tokens_pre);

    let in_consensus = if consensus_vals_pre.contains(storage, &position)? {
        let val_address = consensus_vals_pre.get(storage, &position)?;
        debug_assert!(val_address.is_some());
        val_address == Some(validator.clone())
    } else {
        false
    };

    if in_consensus {
        // It's initially consensus
        tracing::debug!("Target validator is consensus");

        consensus_vals_pre.remove(storage, &position)?;

        let max_below_capacity_validator_amount =
            get_max_below_capacity_validator_amount(
                &below_capacity_val_handle,
                storage,
            )?;

        if tokens_post < max_below_capacity_validator_amount {
            tracing::debug!("Need to swap validators");
            // Place the validator into the below-capacity set and promote the
            // lowest position max below-capacity validator.

            // Remove the max below-capacity validator first
            let below_capacity_vals_max = below_capacity_val_handle
                .at(&max_below_capacity_validator_amount.into());
            let lowest_position =
                find_first_position(&below_capacity_vals_max, storage)?
                    .unwrap();
            let removed_max_below_capacity = below_capacity_vals_max
                .remove(storage, &lowest_position)?
                .expect("Must have been removed");

            // Insert the previous max below-capacity validator into the
            // consensus set
            insert_validator_into_set(
                &consensus_val_handle.at(&max_below_capacity_validator_amount),
                storage,
                &epoch,
                &removed_max_below_capacity,
            )?;
            validator_state_handle(&removed_max_below_capacity).set(
                storage,
                ValidatorState::Consensus,
                current_epoch,
                params.pipeline_len,
            )?;

            // Insert the current validator into the below-capacity set
            insert_validator_into_set(
                &below_capacity_val_handle.at(&tokens_post.into()),
                storage,
                &epoch,
                validator,
            )?;
            validator_state_handle(validator).set(
                storage,
                ValidatorState::BelowCapacity,
                current_epoch,
                params.pipeline_len,
            )?;
        } else {
            tracing::debug!("Validator remains in consensus set");
            // The current validator should remain in the consensus set - place
            // it into a new position
            insert_validator_into_set(
                &consensus_val_handle.at(&tokens_post),
                storage,
                &epoch,
                validator,
            )?;
        }
    } else {
        // TODO: handle the new third set - below threshold

        // It's initially below-capacity
        let below_capacity_vals_pre =
            below_capacity_val_handle.at(&tokens_pre.into());
        let removed = below_capacity_vals_pre.remove(storage, &position)?;
        debug_assert!(removed.is_some());
        debug_assert_eq!(&removed.unwrap(), validator);

        let min_consensus_validator_amount =
            get_min_consensus_validator_amount(&consensus_val_handle, storage)?;

        if tokens_post > min_consensus_validator_amount {
            // Place the validator into the consensus set and demote the last
            // position min consensus validator to the below-capacity set

            // Remove the min consensus validator first
            let consensus_vals_min =
                consensus_val_handle.at(&min_consensus_validator_amount);
            let last_position_of_min_consensus_vals =
                find_last_position(&consensus_vals_min, storage)?.expect(
                    "There must be always be at least 1 consensus validator",
                );
            let removed_min_consensus = consensus_vals_min
                .remove(storage, &last_position_of_min_consensus_vals)?
                .expect(
                    "There must be always be at least 1 consensus validator",
                );

            // Insert the min consensus validator into the below-capacity set
            insert_validator_into_set(
                &below_capacity_val_handle
                    .at(&min_consensus_validator_amount.into()),
                storage,
                &epoch,
                &removed_min_consensus,
            )?;
            validator_state_handle(&removed_min_consensus).set(
                storage,
                ValidatorState::BelowCapacity,
                current_epoch,
                params.pipeline_len,
            )?;

            // Insert the current validator into the consensus set
            insert_validator_into_set(
                &consensus_val_handle.at(&tokens_post),
                storage,
                &epoch,
                validator,
            )?;
            validator_state_handle(validator).set(
                storage,
                ValidatorState::Consensus,
                current_epoch,
                params.pipeline_len,
            )?;
        } else {
            // The current validator should remain in the below-capacity set
            insert_validator_into_set(
                &below_capacity_val_handle.at(&tokens_post.into()),
                storage,
                &epoch,
                validator,
            )?;
            validator_state_handle(validator).set(
                storage,
                ValidatorState::BelowCapacity,
                current_epoch,
                params.pipeline_len,
            )?;
        }
    }
    Ok(())
}

/// Validator sets and positions copying into a future epoch
pub fn copy_validator_sets_and_positions<S>(
    storage: &mut S,
    current_epoch: Epoch,
    target_epoch: Epoch,
    consensus_validator_set: &ConsensusValidatorSets,
    below_capacity_validator_set: &BelowCapacityValidatorSets,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let prev_epoch = target_epoch - 1;

    let (consensus, below_capacity) = (
        consensus_validator_set.at(&prev_epoch),
        below_capacity_validator_set.at(&prev_epoch),
    );
    debug_assert!(!consensus.is_empty(storage)?);

    // Need to copy into memory here to avoid borrowing a ref
    // simultaneously as immutable and mutable
    let mut consensus_in_mem: HashMap<(token::Amount, Position), Address> =
        HashMap::new();
    let mut below_cap_in_mem: HashMap<
        (ReverseOrdTokenAmount, Position),
        Address,
    > = HashMap::new();

    for val in consensus.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: stake,
                nested_sub_key: SubKey::Data(position),
            },
            address,
        ) = val?;
        consensus_in_mem.insert((stake, position), address);
    }
    for val in below_capacity.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: stake,
                nested_sub_key: SubKey::Data(position),
            },
            address,
        ) = val?;
        below_cap_in_mem.insert((stake, position), address);
    }

    tracing::debug!("{consensus_in_mem:?}");

    for ((val_stake, val_position), val_address) in consensus_in_mem.into_iter()
    {
        consensus_validator_set
            .at(&target_epoch)
            .at(&val_stake)
            .insert(storage, val_position, val_address)?;
    }
    tracing::debug!("New validator set should be inserted:");
    tracing::debug!(
        "{:?}",
        read_consensus_validator_set_addresses(storage, target_epoch)?
    );

    for ((val_stake, val_position), val_address) in below_cap_in_mem.into_iter()
    {
        below_capacity_validator_set
            .at(&target_epoch)
            .at(&val_stake)
            .insert(storage, val_position, val_address)?;
    }

    // Copy validator positions
    let mut positions = HashMap::<Address, Position>::default();
    let positions_handle = validator_set_positions_handle().at(&prev_epoch);
    for result in positions_handle.iter(storage)? {
        let (validator, position) = result?;
        positions.insert(validator, position);
    }
    let new_positions_handle =
        validator_set_positions_handle().at(&target_epoch);
    for (validator, position) in positions {
        let prev = new_positions_handle.insert(storage, validator, position)?;
        debug_assert!(prev.is_none());
    }
    validator_set_positions_handle().set_last_update(storage, current_epoch)?;

    Ok(())
}

/// Read the position of the validator in the subset of validators that have the
/// same bonded stake. This information is held in its own epoched structure in
/// addition to being inside the validator sets.
fn read_validator_set_position<S>(
    storage: &S,
    validator: &Address,
    epoch: Epoch,
    params: &PosParams,
) -> storage_api::Result<Option<Position>>
where
    S: StorageRead,
{
    let handle = validator_set_positions_handle();
    handle.get_position(storage, &epoch, validator, params)
}

/// Find the first (lowest) position in a validator set if it is not empty
fn find_first_position<S>(
    handle: &ValidatorPositionAddresses,
    storage: &S,
) -> storage_api::Result<Option<Position>>
where
    S: StorageRead,
{
    let lowest_position = handle
        .iter(storage)?
        .next()
        .transpose()?
        .map(|(position, _addr)| position);
    Ok(lowest_position)
}

/// Find the last (greatest) position in a validator set if it is not empty
fn find_last_position<S>(
    handle: &ValidatorPositionAddresses,
    storage: &S,
) -> storage_api::Result<Option<Position>>
where
    S: StorageRead,
{
    let position = handle
        .iter(storage)?
        .last()
        .transpose()?
        .map(|(position, _addr)| position);
    Ok(position)
}

/// Find next position in a validator set or 0 if empty
fn find_next_position<S>(
    handle: &ValidatorPositionAddresses,
    storage: &S,
) -> storage_api::Result<Position>
where
    S: StorageRead,
{
    let position_iter = handle.iter(storage)?;
    let next = position_iter
        .last()
        .transpose()?
        .map(|(position, _address)| position.next())
        .unwrap_or_default();
    Ok(next)
}

fn get_min_consensus_validator_amount<S>(
    handle: &ConsensusValidatorSet,
    storage: &S,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    Ok(handle
        .iter(storage)?
        .next()
        .transpose()?
        .map(|(subkey, _address)| match subkey {
            NestedSubKey::Data {
                key,
                nested_sub_key: _,
            } => key,
        })
        .unwrap_or_default())
}

fn get_max_below_capacity_validator_amount<S>(
    handle: &BelowCapacityValidatorSet,
    storage: &S,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    Ok(handle
        .iter(storage)?
        .next()
        .transpose()?
        .map(|(subkey, _address)| match subkey {
            NestedSubKey::Data {
                key,
                nested_sub_key: _,
            } => key,
        })
        .unwrap_or_default()
        .into())
}

fn insert_validator_into_set<S>(
    handle: &ValidatorPositionAddresses,
    storage: &mut S,
    epoch: &Epoch,
    address: &Address,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let next_position = find_next_position(handle, storage)?;
    tracing::debug!(
        "Inserting validator {} into position {:?} at epoch {}",
        address.clone(),
        next_position.clone(),
        epoch.clone()
    );
    handle.insert(storage, next_position, address.clone())?;
    validator_set_positions_handle().at(epoch).insert(
        storage,
        address.clone(),
        next_position,
    )?;
    Ok(())
}

/// Unbond.
pub fn unbond_tokens<S>(
    storage: &mut S,
    source: Option<&Address>,
    validator: &Address,
    amount: token::Amount,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let amount = amount.change();
    tracing::debug!("Unbonding token amount {amount} at epoch {current_epoch}");
    let params = read_pos_params(storage)?;
    let pipeline_epoch = current_epoch + params.pipeline_len;
    tracing::debug!(
        "Current validator stake at pipeline: {}",
        read_validator_stake(storage, &params, validator, pipeline_epoch)?
            .unwrap_or_default()
    );

    if let Some(source) = source {
        if source != validator
            && is_validator(storage, source, &params, pipeline_epoch)?
        {
            return Err(
                BondError::SourceMustNotBeAValidator(source.clone()).into()
            );
        }
    }
    if !is_validator(storage, validator, &params, pipeline_epoch)? {
        return Err(BondError::NotAValidator(validator.clone()).into());
    }

    // TODO: Should be able to unbond inactive validators, but we'll need to
    // prevent jailed unbonding with slashing
    // let validator_state_handle = validator_state_handle(validator);
    // for epoch in current_epoch.iter_range(params.pipeline_len) {
    //     if let Some(ValidatorState::Inactive) =
    //         validator_state_handle.get(storage, epoch, &params)?
    //     {
    //         return
    // Err(BondError::InactiveValidator(validator.clone()).into());     }
    // }

    let source = source.unwrap_or(validator);
    let _bond_amount_handle = bond_handle(source, validator);
    let bond_remain_handle = bond_handle(source, validator);

    // Make sure there are enough tokens left in the bond at the pipeline offset
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let remaining_at_pipeline = bond_remain_handle
        .get_sum(storage, pipeline_epoch, &params)?
        .unwrap_or_default();
    if amount > remaining_at_pipeline {
        return Err(UnbondError::UnbondAmountGreaterThanBond(
            token::Amount::from_change(amount),
            token::Amount::from_change(remaining_at_pipeline),
        )
        .into());
    }

    // Iterate thru this, find non-zero delta entries starting from most recent,
    // then just start decrementing those values For every delta val that
    // gets decremented down to 0, need a unique unbond object to have a clear
    // start epoch

    // TODO: do we want to apply slashing here? (It is done here previously)

    let unbond_handle = unbond_handle(source, validator);
    let withdrawable_epoch =
        current_epoch + params.pipeline_len + params.unbonding_len;
    let mut to_decrement = token::Amount::from_change(amount);

    // We read all matched bonds into memory to do reverse iteration
    #[allow(clippy::needless_collect)]
    let bonds: Vec<Result<_, _>> = bond_remain_handle
        .get_data_handler()
        .iter(storage)?
        .collect();
    // tracing::debug!("Bonds before decrementing:");
    // for ep in Epoch::default().iter_range(params.unbonding_len * 3) {
    //     tracing::debug!(
    //         "bond delta at epoch {}: {}",
    //         ep,
    //         bond_remain_handle
    //             .get_delta_val(storage, ep, &params)?
    //             .unwrap_or_default()
    //     )
    // }
    let mut bond_iter = bonds.into_iter().rev();

    // Map: { bond start epoch, (new bond value, unbond value) }
    let mut new_bond_values_map =
        HashMap::<Epoch, (token::Amount, token::Amount)>::new();

    while to_decrement > token::Amount::default() {
        let bond = bond_iter.next().transpose()?;
        if bond.is_none() {
            continue;
        }
        let (bond_epoch, bond_amnt) = bond.unwrap();
        let bond_amnt = token::Amount::from_change(bond_amnt);

        if to_decrement < bond_amnt {
            // Decrement the amount in this bond and create the unbond object
            // with amount `to_decrement` and starting epoch `bond_epoch`
            let new_bond_amnt = bond_amnt - to_decrement;
            new_bond_values_map
                .insert(bond_epoch, (new_bond_amnt, to_decrement));
            to_decrement = token::Amount::default();
        } else {
            // Set the bond remaining delta to 0 then continue decrementing
            new_bond_values_map
                .insert(bond_epoch, (token::Amount::default(), bond_amnt));
            to_decrement -= bond_amnt;
        }
    }
    drop(bond_iter);

    // Write the in-memory bond and unbond values back to storage
    for (bond_epoch, (new_bond_amnt, unbond_amnt)) in
        new_bond_values_map.into_iter()
    {
        bond_remain_handle.set(storage, new_bond_amnt.into(), bond_epoch, 0)?;
        update_unbond(
            &unbond_handle,
            storage,
            &withdrawable_epoch,
            &bond_epoch,
            unbond_amnt,
        )?;
    }

    // tracing::debug!("Bonds after decrementing:");
    // for ep in Epoch::default().iter_range(params.unbonding_len * 3) {
    //     tracing::debug!(
    //         "bond delta at epoch {}: {}",
    //         ep,
    //         bond_remain_handle
    //             .get_delta_val(storage, ep, &params)?
    //             .unwrap_or_default()
    //     )
    // }

    tracing::debug!("Updating validator set for unbonding");
    // Update the validator set at the pipeline offset
    update_validator_set(storage, &params, validator, -amount, current_epoch)?;

    // Update the validator and total deltas at the pipeline offset
    update_validator_deltas(
        storage,
        &params,
        validator,
        -amount,
        current_epoch,
    )?;
    update_total_deltas(storage, &params, -amount, current_epoch)?;

    Ok(())
}

fn update_unbond<S>(
    handle: &Unbonds,
    storage: &mut S,
    withdraw_epoch: &Epoch,
    start_epoch: &Epoch,
    amount: token::Amount,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let current = handle
        .at(withdraw_epoch)
        .get(storage, start_epoch)?
        .unwrap_or_default();
    handle.at(withdraw_epoch).insert(
        storage,
        *start_epoch,
        current + amount,
    )?;
    Ok(())
}

/// Initialize data for a new validator.
pub fn become_validator<S>(
    storage: &mut S,
    params: &PosParams,
    address: &Address,
    consensus_key: &common::PublicKey,
    current_epoch: Epoch,
    commission_rate: Decimal,
    max_commission_rate_change: Decimal,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    // This will fail if the key is already being used
    try_insert_consensus_key(storage, consensus_key)?;

    // Non-epoched validator data
    write_validator_address_raw_hash(storage, address, consensus_key)?;
    write_validator_max_commission_rate_change(
        storage,
        address,
        max_commission_rate_change,
    )?;

    // Epoched validator data
    validator_consensus_key_handle(address).set(
        storage,
        consensus_key.clone(),
        current_epoch,
        params.pipeline_len,
    )?;
    validator_commission_rate_handle(address).set(
        storage,
        commission_rate,
        current_epoch,
        params.pipeline_len,
    )?;
    validator_deltas_handle(address).set(
        storage,
        token::Change::default(),
        current_epoch,
        params.pipeline_len,
    )?;

    let stake = token::Amount::default();

    insert_validator_into_validator_set(
        storage,
        params,
        address,
        stake,
        current_epoch,
        params.pipeline_len,
    )?;
    Ok(())
}

/// Withdraw.
pub fn withdraw_tokens<S>(
    storage: &mut S,
    source: Option<&Address>,
    validator: &Address,
    current_epoch: Epoch,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead + StorageWrite,
{
    tracing::debug!("Withdrawing tokens in epoch {current_epoch}");
    let params = read_pos_params(storage)?;
    let source = source.unwrap_or(validator);

    let slashes = validator_slashes_handle(validator);
    let unbond_handle = unbond_handle(source, validator);

    let mut slashed = token::Amount::default();
    let mut withdrawable_amount = token::Amount::default();
    let mut unbonds_to_remove: Vec<(Epoch, Epoch)> = Vec::new();
    // TODO: use `find_unbonds`
    let unbond_iter = unbond_handle.iter(storage)?;
    for unbond in unbond_iter {
        let (
            NestedSubKey::Data {
                key: withdraw_epoch,
                nested_sub_key: SubKey::Data(start_epoch),
            },
            amount,
        ) = unbond?;

        tracing::debug!(
            "Unbond delta ({start_epoch}..{withdraw_epoch}), amount {amount}",
        );

        // TODO: worry about updating this later after PR 740 perhaps
        // 1. cubic slashing
        // 2. adding slash rates in same epoch, applying cumulatively in dif
        // epochs
        if withdraw_epoch > current_epoch {
            tracing::debug!("Not yet withdrawable");
            continue;
        }
        for slash in slashes.iter(storage)? {
            let Slash {
                epoch,
                block_height: _,
                r#type: slash_type,
            } = slash?;
            if epoch > start_epoch
                && epoch
                    < withdraw_epoch
                        .checked_sub(Epoch(params.unbonding_len))
                        .unwrap_or_default()
            {
                let slash_rate = slash_type.get_slash_rate(&params);
                let to_slash = token::Amount::from(decimal_mult_u64(
                    slash_rate,
                    u64::from(amount),
                ));
                slashed += to_slash;
            }
        }
        withdrawable_amount += amount;
        unbonds_to_remove.push((withdraw_epoch, start_epoch));
    }
    withdrawable_amount -= slashed;
    tracing::debug!("Withdrawing total {withdrawable_amount}");

    // Remove the unbond data from storage
    for (withdraw_epoch, start_epoch) in unbonds_to_remove {
        tracing::debug!("Remove ({start_epoch}..{withdraw_epoch}) from unbond");
        unbond_handle
            .at(&withdraw_epoch)
            .remove(storage, &start_epoch)?;
        // TODO: check if the `end_epoch` layer is now empty and remove it if
        // so, may need to implement remove/delete for nested map
    }

    // Transfer the tokens from the PoS address back to the source
    transfer_tokens(
        storage,
        &staking_token_address(),
        withdrawable_amount,
        &ADDRESS,
        source,
    )?;

    Ok(withdrawable_amount)
}

/// Change the commission rate of a validator
pub fn change_validator_commission_rate<S>(
    storage: &mut S,
    validator: &Address,
    new_rate: Decimal,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    if new_rate < Decimal::ZERO {
        return Err(CommissionRateChangeError::NegativeRate(
            new_rate,
            validator.clone(),
        )
        .into());
    }

    let max_change =
        read_validator_max_commission_rate_change(storage, validator)?;
    if max_change.is_none() {
        return Err(CommissionRateChangeError::NoMaxSetInStorage(
            validator.clone(),
        )
        .into());
    }

    let params = read_pos_params(storage)?;
    let commission_handle = validator_commission_rate_handle(validator);
    let pipeline_epoch = current_epoch + params.pipeline_len;

    let rate_at_pipeline = commission_handle
        .get(storage, pipeline_epoch, &params)?
        .expect("Could not find a rate in given epoch");
    if new_rate == rate_at_pipeline {
        return Ok(());
    }
    let rate_before_pipeline = commission_handle
        .get(storage, pipeline_epoch - 1, &params)?
        .expect("Could not find a rate in given epoch");
    let change_from_prev = new_rate - rate_before_pipeline;
    if change_from_prev.abs() > max_change.unwrap() {
        return Err(CommissionRateChangeError::RateChangeTooLarge(
            change_from_prev,
            validator.clone(),
        )
        .into());
    }

    commission_handle.set(storage, new_rate, current_epoch, params.pipeline_len)
}

/// apply a slash and write it to storage
pub fn slash<S>(
    storage: &mut S,
    params: &PosParams,
    current_epoch: Epoch,
    evidence_epoch: Epoch,
    evidence_block_height: impl Into<u64>,
    slash_type: SlashType,
    validator: &Address,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let rate = slash_type.get_slash_rate(params);
    let slash = Slash {
        epoch: evidence_epoch,
        block_height: evidence_block_height.into(),
        r#type: slash_type,
    };

    let current_stake =
        read_validator_stake(storage, params, validator, current_epoch)?
            .unwrap_or_default();
    let slashed_amount = decimal_mult_u64(rate, u64::from(current_stake));
    let token_change = -token::Change::from(slashed_amount);

    // Update validator sets and deltas at the pipeline length
    update_validator_set(
        storage,
        params,
        validator,
        token_change,
        current_epoch,
    )?;
    update_validator_deltas(
        storage,
        params,
        validator,
        token_change,
        current_epoch,
    )?;
    update_total_deltas(storage, params, token_change, current_epoch)?;

    // Write the validator slash to storage
    validator_slashes_handle(validator).push(storage, slash)?;

    // Transfer the slashed tokens from PoS account to Slash Fund address
    transfer_tokens(
        storage,
        &staking_token_address(),
        token::Amount::from(slashed_amount),
        &ADDRESS,
        &SLASH_POOL_ADDRESS,
    )?;

    Ok(())
}

/// Transfer tokens between accounts
/// TODO: may want to move this into core crate
pub fn transfer_tokens<S>(
    storage: &mut S,
    token: &Address,
    amount: token::Amount,
    src: &Address,
    dest: &Address,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let src_key = token::balance_key(token, src);
    let dest_key = token::balance_key(token, dest);
    if let Some(mut src_balance) = storage.read::<token::Amount>(&src_key)? {
        // let mut src_balance: token::Amount =
        //     decode(src_balance).unwrap_or_default();
        if src_balance < amount {
            tracing::error!(
                "PoS system transfer error, the source doesn't have \
                 sufficient balance. It has {}, but {} is required",
                src_balance,
                amount
            );
        }
        src_balance.spend(&amount);
        let mut dest_balance = storage
            .read::<token::Amount>(&dest_key)?
            .unwrap_or_default();

        // let dest_balance = storage.read_bytes(&dest_key).unwrap_or_default();
        // let mut dest_balance: token::Amount = dest_balance
        //     .and_then(|b| decode(b).ok())
        //     .unwrap_or_default();
        dest_balance.receive(&amount);
        storage
            .write(&src_key, src_balance)
            .expect("Unable to write token balance for PoS system");
        storage
            .write(&dest_key, dest_balance)
            .expect("Unable to write token balance for PoS system");
    } else {
        tracing::error!("PoS system transfer error, the source has no balance");
    }
    Ok(())
}

/// Check if the given consensus key is already being used to ensure uniqueness.
///
/// If it's not being used, it will be inserted into the set that's being used
/// for this. If it's already used, this will return an Error.
pub fn try_insert_consensus_key<S>(
    storage: &mut S,
    consensus_key: &common::PublicKey,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = consensus_keys_key();
    LazySet::open(key).try_insert(storage, consensus_key.clone())
}

/// Check if the given consensus key is already being used to ensure uniqueness.
pub fn is_consensus_key_used<S>(
    storage: &S,
    consensus_key: &common::PublicKey,
) -> storage_api::Result<bool>
where
    S: StorageRead,
{
    let key = consensus_keys_key();
    let handle = LazySet::open(key);
    handle.contains(storage, consensus_key)
}

/// Get the total bond amount for a given bond ID at a given epoch
pub fn bond_amount<S>(
    storage: &S,
    params: &PosParams,
    bond_id: &BondId,
    epoch: Epoch,
) -> storage_api::Result<(token::Amount, token::Amount)>
where
    S: StorageRead,
{
    // TODO: review this logic carefully, do cubic slashing, apply rewards
    let slashes = find_validator_slashes(storage, &bond_id.validator)?;
    let bonds =
        bond_handle(&bond_id.source, &bond_id.validator).get_data_handler();
    let mut total = token::Amount::default();
    let mut total_active = token::Amount::default();
    for next in bonds.iter(storage)? {
        let (bond_epoch, delta) = next?;
        // if bond_epoch > epoch {
        //     break;
        // }
        for slash in slashes.iter() {
            let Slash {
                epoch: slash_epoch,
                block_height: _,
                r#type: slash_type,
            } = slash;
            if slash_epoch > &bond_epoch {
                continue;
            }
            let current_slashed =
                decimal_mult_i128(slash_type.get_slash_rate(params), delta);
            let delta = token::Amount::from_change(delta - current_slashed);
            total += delta;
            if bond_epoch <= epoch {
                total_active += delta;
            }
        }
    }
    Ok((total, total_active))
}

/// Update tendermint validator set
pub fn validator_set_update_tendermint<S, T>(
    storage: &S,
    params: &PosParams,
    current_epoch: Epoch,
    f: impl FnMut(ValidatorSetUpdate) -> T,
) -> storage_api::Result<Vec<T>>
where
    S: StorageRead,
{
    let current_epoch: Epoch = current_epoch;
    let current_epoch_u64: u64 = current_epoch.into();

    let previous_epoch: Option<Epoch> = if current_epoch_u64 == 0 {
        None
    } else {
        Some(Epoch::from(current_epoch_u64 - 1))
    };

    let cur_consensus_validators =
        consensus_validator_set_handle().at(&current_epoch);
    let prev_consensus_validators = previous_epoch.map(|previous_epoch| {
        consensus_validator_set_handle().at(&previous_epoch)
    });

    let consensus_validators = cur_consensus_validators
        .iter(storage)?
        .filter_map(|validator| {
            let (
                NestedSubKey::Data {
                    key: cur_stake,
                    nested_sub_key: _,
                },
                address,
            ) = validator.unwrap();

            tracing::debug!(
                "Consensus validator address {address}, stake {cur_stake}"
            );

            // Check if the validator was consensus in the previous epoch with
            // the same stake
            if prev_consensus_validators.is_some() {
                if let Some(prev_epoch) = previous_epoch {
                    // Look up previous state and prev and current voting powers
                    let prev_state = validator_state_handle(&address)
                        .get(storage, prev_epoch, params)
                        .unwrap();
                    let prev_tm_voting_power = Lazy::new(|| {
                        let prev_validator_stake =
                            validator_deltas_handle(&address)
                                .get_sum(storage, prev_epoch, params)
                                .unwrap()
                                .map(token::Amount::from_change)
                                .unwrap_or_default();
                        into_tm_voting_power(
                            params.tm_votes_per_token,
                            prev_validator_stake,
                        )
                    });
                    let cur_tm_voting_power = Lazy::new(|| {
                        into_tm_voting_power(
                            params.tm_votes_per_token,
                            cur_stake,
                        )
                    });

                    // If its was in `Consensus` before and voting power has not
                    // changed, skip the update
                    if matches!(prev_state, Some(ValidatorState::Consensus))
                        && *prev_tm_voting_power == *cur_tm_voting_power
                    {
                        tracing::debug!(
                            "skipping validator update, {address} is in \
                             consensus set but voting power hasn't changed"
                        );
                        return None;
                    }

                    // If both previous and current voting powers are 0, skip
                    // update
                    if *prev_tm_voting_power == 0 && *cur_tm_voting_power == 0 {
                        tracing::info!(
                            "skipping validator update, {address} is in \
                             consensus set but without voting power"
                        );
                        return None;
                    }
                }
            }
            let consensus_key = validator_consensus_key_handle(&address)
                .get(storage, current_epoch, params)
                .unwrap()
                .unwrap();
            tracing::debug!(
                "{address} consensus key {}",
                consensus_key.tm_raw_hash()
            );
            Some(ValidatorSetUpdate::Consensus(ConsensusValidator {
                consensus_key,
                bonded_stake: cur_stake.into(),
            }))
        });
    let cur_below_capacity_validators =
        below_capacity_validator_set_handle().at(&current_epoch);
    let below_capacity_validators = cur_below_capacity_validators
        .iter(storage)
        .unwrap()
        .filter_map(|validator| {
            let (
                NestedSubKey::Data {
                    key: cur_stake,
                    nested_sub_key: _,
                },
                address,
            ) = validator.unwrap();
            let cur_stake = token::Amount::from(cur_stake);

            tracing::debug!(
                "Below-capacity validator address {address}, stake {cur_stake}"
            );

            let prev_tm_voting_power = previous_epoch
                .map(|prev_epoch| {
                    let prev_validator_stake =
                        validator_deltas_handle(&address)
                            .get_sum(storage, prev_epoch, params)
                            .unwrap()
                            .map(token::Amount::from_change)
                            .unwrap_or_default();
                    into_tm_voting_power(
                        params.tm_votes_per_token,
                        prev_validator_stake,
                    )
                })
                .unwrap_or_default();

            // If the validator previously had no voting power, it wasn't in
            // tendermint set and we have to skip it.
            if prev_tm_voting_power == 0 {
                tracing::debug!(
                    "skipping validator update {address}, it's inactive and \
                     previously had no voting power"
                );
                return None;
            }

            let prev_below_capacity_vals =
                below_capacity_validator_set_handle()
                    .at(&previous_epoch.unwrap());
            if !prev_below_capacity_vals.is_empty(storage).unwrap() {
                if let Some(prev_epoch) = previous_epoch {
                    // Look up the previous state
                    let prev_state = validator_state_handle(&address)
                        .get(storage, prev_epoch, params)
                        .unwrap();
                    // If the `prev_state.is_none()`, it's a new validator that
                    // is `BelowCapacity`, so no update is needed. If it
                    // previously was `BelowCapacity` there's no update needed
                    // either.
                    if !matches!(prev_state, Some(ValidatorState::Consensus)) {
                        tracing::debug!(
                            "skipping validator update, {address} is not and \
                             wasn't previously in consensus set"
                        );
                        return None;
                    }
                }
            }

            let consensus_key = validator_consensus_key_handle(&address)
                .get(storage, current_epoch, params)
                .unwrap()
                .unwrap();
            tracing::debug!(
                "{address} consensus key {}",
                consensus_key.tm_raw_hash()
            );
            Some(ValidatorSetUpdate::Deactivated(consensus_key))
        });
    Ok(consensus_validators
        .chain(below_capacity_validators)
        .map(f)
        .collect())
}

/// Find all validators to which a given bond `owner` (or source) has a
/// delegation
pub fn find_delegation_validators<S>(
    storage: &S,
    owner: &Address,
) -> storage_api::Result<HashSet<Address>>
where
    S: StorageRead,
{
    let bonds_prefix = bonds_for_source_prefix(owner);
    let mut delegations: HashSet<Address> = HashSet::new();

    for iter_result in storage_api::iter_prefix_bytes(storage, &bonds_prefix)? {
        let (key, _bond_bytes) = iter_result?;
        let validator_address = get_validator_address_from_bond(&key)
            .ok_or_else(|| {
                storage_api::Error::new_const(
                    "Delegation key should contain validator address.",
                )
            })?;
        delegations.insert(validator_address);
    }
    Ok(delegations)
}

/// Find all validators to which a given bond `owner` (or source) has a
/// delegation with the amount
pub fn find_delegations<S>(
    storage: &S,
    owner: &Address,
    epoch: &Epoch,
) -> storage_api::Result<HashMap<Address, token::Amount>>
where
    S: StorageRead,
{
    let bonds_prefix = bonds_for_source_prefix(owner);
    let params = read_pos_params(storage)?;
    let mut delegations: HashMap<Address, token::Amount> = HashMap::new();

    for iter_result in storage_api::iter_prefix_bytes(storage, &bonds_prefix)? {
        let (key, _bond_bytes) = iter_result?;
        let validator_address = get_validator_address_from_bond(&key)
            .ok_or_else(|| {
                storage_api::Error::new_const(
                    "Delegation key should contain validator address.",
                )
            })?;
        let amount = bond_handle(owner, &validator_address)
            .get_sum(storage, *epoch, &params)?
            .unwrap_or_default();
        delegations
            .insert(validator_address, token::Amount::from_change(amount));
    }
    Ok(delegations)
}

/// Find PoS slashes applied to a validator, if any
pub fn find_validator_slashes<S>(
    storage: &S,
    validator: &Address,
) -> storage_api::Result<Vec<Slash>>
where
    S: StorageRead,
{
    validator_slashes_handle(validator).iter(storage)?.collect()
}

/// Find bond deltas for the given source and validator address.
pub fn find_bonds<S>(
    storage: &S,
    source: &Address,
    validator: &Address,
) -> storage_api::Result<BTreeMap<Epoch, token::Change>>
where
    S: StorageRead,
{
    bond_handle(source, validator)
        .get_data_handler()
        .iter(storage)?
        .collect()
}

/// Find unbond deltas for the given source and validator address.
pub fn find_unbonds<S>(
    storage: &S,
    source: &Address,
    validator: &Address,
) -> storage_api::Result<BTreeMap<(Epoch, Epoch), token::Amount>>
where
    S: StorageRead,
{
    unbond_handle(source, validator)
        .iter(storage)?
        .map(|next_result| {
            let (
                NestedSubKey::Data {
                    key: withdraw_epoch,
                    nested_sub_key: SubKey::Data(start_epoch),
                },
                amount,
            ) = next_result?;
            Ok(((start_epoch, withdraw_epoch), amount))
        })
        .collect()
}

/// Collect the details of all bonds and unbonds that match the source and
/// validator arguments. If either source or validator is `None`, then grab the
/// information for all sources or validators, respectively.
pub fn bonds_and_unbonds<S>(
    storage: &S,
    source: Option<Address>,
    validator: Option<Address>,
) -> storage_api::Result<BondsAndUnbondsDetails>
where
    S: StorageRead,
{
    let params = read_pos_params(storage)?;

    match (source.clone(), validator.clone()) {
        (Some(source), Some(validator)) => {
            find_bonds_and_unbonds_details(storage, &params, source, validator)
        }
        _ => {
            get_multiple_bonds_and_unbonds(storage, &params, source, validator)
        }
    }
}

/// Find all slashes and the associated validators in the PoS system
pub fn find_all_slashes<S>(
    storage: &S,
) -> storage_api::Result<HashMap<Address, Vec<Slash>>>
where
    S: StorageRead,
{
    let mut slashes: HashMap<Address, Vec<Slash>> = HashMap::new();
    let slashes_iter = storage_api::iter_prefix_bytes(
        storage,
        &slashes_prefix(),
    )?
    .filter_map(|result| {
        if let Ok((key, val_bytes)) = result {
            if let Some(validator) = is_validator_slashes_key(&key) {
                let slash: Slash =
                    BorshDeserialize::try_from_slice(&val_bytes).ok()?;
                return Some((validator, slash));
            }
        }
        None
    });

    slashes_iter.for_each(|(address, slash)| match slashes.get(&address) {
        Some(vec) => {
            let mut vec = vec.clone();
            vec.push(slash);
            slashes.insert(address, vec);
        }
        None => {
            slashes.insert(address, vec![slash]);
        }
    });
    Ok(slashes)
}

fn get_multiple_bonds_and_unbonds<S>(
    storage: &S,
    params: &PosParams,
    source: Option<Address>,
    validator: Option<Address>,
) -> storage_api::Result<BondsAndUnbondsDetails>
where
    S: StorageRead,
{
    debug_assert!(
        source.is_none() || validator.is_none(),
        "Use `find_bonds_and_unbonds_details` when full bond ID is known"
    );
    let mut slashes_cache = HashMap::<Address, Vec<Slash>>::new();
    // Applied slashes grouped by validator address
    let mut applied_slashes = HashMap::<Address, HashSet<Slash>>::new();

    // TODO: if validator is `Some`, look-up all its bond owners (including
    // self-bond, if any) first

    let prefix = match source.as_ref() {
        Some(source) => bonds_for_source_prefix(source),
        None => bonds_prefix(),
    };
    // We have to iterate raw bytes, cause the epoched data `last_update` field
    // gets matched here too
    let mut raw_bonds = storage_api::iter_prefix_bytes(storage, &prefix)?
        .filter_map(|result| {
            if let Ok((key, val_bytes)) = result {
                if let Some((bond_id, start)) = is_bond_key(&key) {
                    if source.is_some()
                        && source.as_ref().unwrap() != &bond_id.source
                    {
                        return None;
                    }
                    if validator.is_some()
                        && validator.as_ref().unwrap() != &bond_id.validator
                    {
                        return None;
                    }
                    let change: token::Change =
                        BorshDeserialize::try_from_slice(&val_bytes).ok()?;
                    return Some((bond_id, start, change));
                }
            }
            None
        });

    let prefix = match source.as_ref() {
        Some(source) => unbonds_for_source_prefix(source),
        None => unbonds_prefix(),
    };
    let mut raw_unbonds = storage_api::iter_prefix_bytes(storage, &prefix)?
        .filter_map(|result| {
            if let Ok((key, val_bytes)) = result {
                if let Some((_bond_id, _start, withdraw)) = is_unbond_key(&key)
                {
                    if let Some((bond_id, start)) = is_bond_key(&key) {
                        if source.is_some()
                            && source.as_ref().unwrap() != &bond_id.source
                        {
                            return None;
                        }
                        if validator.is_some()
                            && validator.as_ref().unwrap() != &bond_id.validator
                        {
                            return None;
                        }
                        let amount: token::Amount =
                            BorshDeserialize::try_from_slice(&val_bytes)
                                .ok()?;
                        return Some((bond_id, start, withdraw, amount));
                    }
                }
            }
            None
        });

    let mut bonds_and_unbonds =
        HashMap::<BondId, (Vec<BondDetails>, Vec<UnbondDetails>)>::new();

    raw_bonds.try_for_each(|(bond_id, start, change)| {
        if !slashes_cache.contains_key(&bond_id.validator) {
            let slashes = find_validator_slashes(storage, &bond_id.validator)?;
            slashes_cache.insert(bond_id.validator.clone(), slashes);
        }
        let slashes = slashes_cache
            .get(&bond_id.validator)
            .expect("We must have inserted it if it's not cached already");
        let validator = bond_id.validator.clone();
        let (bonds, _unbonds) = bonds_and_unbonds.entry(bond_id).or_default();
        bonds.push(make_bond_details(
            storage,
            params,
            &validator,
            change,
            start,
            slashes,
            &mut applied_slashes,
        ));
        Ok::<_, storage_api::Error>(())
    })?;

    raw_unbonds.try_for_each(|(bond_id, start, withdraw, amount)| {
        if !slashes_cache.contains_key(&bond_id.validator) {
            let slashes = find_validator_slashes(storage, &bond_id.validator)?;
            slashes_cache.insert(bond_id.validator.clone(), slashes);
        }
        let slashes = slashes_cache
            .get(&bond_id.validator)
            .expect("We must have inserted it if it's not cached already");
        let validator = bond_id.validator.clone();
        let (_bonds, unbonds) = bonds_and_unbonds.entry(bond_id).or_default();
        unbonds.push(make_unbond_details(
            storage,
            params,
            &validator,
            amount,
            (start, withdraw),
            slashes,
            &mut applied_slashes,
        ));
        Ok::<_, storage_api::Error>(())
    })?;

    Ok(bonds_and_unbonds
        .into_iter()
        .map(|(bond_id, (bonds, unbonds))| {
            let details = BondsAndUnbondsDetail {
                bonds,
                unbonds,
                slashes: applied_slashes
                    .get(&bond_id.validator)
                    .cloned()
                    .unwrap_or_default(),
            };
            (bond_id, details)
        })
        .collect())
}

fn find_bonds_and_unbonds_details<S>(
    storage: &S,
    params: &PosParams,
    source: Address,
    validator: Address,
) -> storage_api::Result<BondsAndUnbondsDetails>
where
    S: StorageRead,
{
    let slashes = find_validator_slashes(storage, &validator)?;
    let mut applied_slashes = HashMap::<Address, HashSet<Slash>>::new();

    let bonds = find_bonds(storage, &source, &validator)?
        .into_iter()
        .map(|(start, change)| {
            make_bond_details(
                storage,
                params,
                &validator,
                change,
                start,
                &slashes,
                &mut applied_slashes,
            )
        })
        .collect();

    let unbonds = find_unbonds(storage, &source, &validator)?
        .into_iter()
        .map(|(epoch_range, change)| {
            make_unbond_details(
                storage,
                params,
                &validator,
                change,
                epoch_range,
                &slashes,
                &mut applied_slashes,
            )
        })
        .collect();

    let details = BondsAndUnbondsDetail {
        bonds,
        unbonds,
        slashes: applied_slashes.get(&validator).cloned().unwrap_or_default(),
    };
    let bond_id = BondId { source, validator };
    Ok(HashMap::from_iter([(bond_id, details)]))
}

fn make_bond_details<S>(
    _storage: &S,
    params: &PosParams,
    validator: &Address,
    change: token::Change,
    start: Epoch,
    slashes: &[Slash],
    applied_slashes: &mut HashMap<Address, HashSet<Slash>>,
) -> BondDetails {
    let amount = token::Amount::from_change(change);
    let slashed_amount =
        slashes
            .iter()
            .fold(None, |acc: Option<token::Amount>, slash| {
                if slash.epoch >= start {
                    let validator_slashes =
                        applied_slashes.entry(validator.clone()).or_default();
                    if !validator_slashes.contains(slash) {
                        validator_slashes.insert(slash.clone());
                    }
                    return Some(
                        acc.unwrap_or_default()
                            + mult_change_to_amount(
                                slash.r#type.get_slash_rate(params),
                                change,
                            ),
                    );
                }
                None
            });
    BondDetails {
        start,
        amount,
        slashed_amount,
    }
}

fn make_unbond_details<S>(
    _storage: &S,
    params: &PosParams,
    validator: &Address,
    amount: token::Amount,
    (start, withdraw): (Epoch, Epoch),
    slashes: &[Slash],
    applied_slashes: &mut HashMap<Address, HashSet<Slash>>,
) -> UnbondDetails {
    let slashed_amount =
        slashes
            .iter()
            .fold(None, |acc: Option<token::Amount>, slash| {
                if slash.epoch >= start
                    && slash.epoch
                        < withdraw
                            .checked_sub(Epoch(params.unbonding_len))
                            .unwrap_or_default()
                {
                    let validator_slashes =
                        applied_slashes.entry(validator.clone()).or_default();
                    if !validator_slashes.contains(slash) {
                        validator_slashes.insert(slash.clone());
                    }
                    return Some(
                        acc.unwrap_or_default()
                            + mult_amount(
                                slash.r#type.get_slash_rate(params),
                                amount,
                            ),
                    );
                }
                None
            });
    UnbondDetails {
        start,
        withdraw,
        amount,
        slashed_amount,
    }
}
