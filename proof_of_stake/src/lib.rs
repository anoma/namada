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
pub mod pos_queries;
pub mod rewards;
pub mod storage;
pub mod types;
// pub mod validation;

#[cfg(test)]
mod tests;

use core::fmt::Debug;
use std::cmp::{self, Reverse};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::num::TryFromIntError;

use borsh::BorshDeserialize;
use namada_core::ledger::storage_api::collections::lazy_map::{
    Collectable, LazyMap, NestedMap, NestedSubKey, SubKey,
};
use namada_core::ledger::storage_api::collections::{LazyCollection, LazySet};
use namada_core::ledger::storage_api::token::credit_tokens;
use namada_core::ledger::storage_api::{
    self, ResultExt, StorageRead, StorageWrite,
};
use namada_core::types::address::{Address, InternalAddress};
use namada_core::types::dec::Dec;
use namada_core::types::key::{
    common, tm_consensus_key_raw_hash, PublicKeyTmRawHash,
};
pub use namada_core::types::storage::{Epoch, Key, KeySeg};
use namada_core::types::token;
use once_cell::unsync::Lazy;
use parameters::PosParams;
use rewards::PosRewardsCalculator;
use storage::{
    bonds_for_source_prefix, bonds_prefix, consensus_keys_key,
    get_validator_address_from_bond, into_tm_voting_power, is_bond_key,
    is_unbond_key, is_validator_slashes_key, last_block_proposer_key,
    params_key, slashes_prefix, unbonds_for_source_prefix, unbonds_prefix,
    validator_address_raw_hash_key, validator_last_slash_key,
    validator_max_commission_rate_change_key, BondDetails,
    BondsAndUnbondsDetail, BondsAndUnbondsDetails, DelegatorRedelegatedBonded,
    DelegatorRedelegatedUnbonded, EpochedSlashes, IncomingRedelegations,
    OutgoingRedelegations, Redelegation, ReverseOrdTokenAmount,
    RewardsAccumulator, SlashedAmount, TotalConsensusStakes,
    TotalRedelegatedBonded, TotalRedelegatedUnbonded, UnbondDetails,
    ValidatorAddresses, ValidatorUnbondRecords,
};
use thiserror::Error;
use types::{
    BelowCapacityValidatorSet, BelowCapacityValidatorSets, BondId, Bonds,
    CommissionRates, ConsensusValidator, ConsensusValidatorSet,
    ConsensusValidatorSets, EagerRedelegatedBondsMap, GenesisValidator,
    Position, RedelegatedBonds, RewardsProducts, Slash, SlashType, Slashes,
    TotalDeltas, Unbonds, ValidatorConsensusKeys, ValidatorDeltas,
    ValidatorEthColdKeys, ValidatorEthHotKeys, ValidatorPositionAddresses,
    ValidatorSetPositions, ValidatorSetUpdate, ValidatorState, ValidatorStates,
    VoteInfo, WeightedValidator,
};

/// Address of the PoS account implemented as a native VP
pub const ADDRESS: Address = Address::Internal(InternalAddress::PoS);

/// Address of the PoS slash pool account
pub const SLASH_POOL_ADDRESS: Address =
    Address::Internal(InternalAddress::PosSlashPool);

/// Address of the staking token (i.e. the native token)
pub fn staking_token_address(storage: &impl StorageRead) -> Address {
    storage
        .get_native_token()
        .expect("Must be able to read native token address")
}

/// Number of epochs below the current epoch for which full validator sets are
/// stored
const STORE_VALIDATOR_SETS_LEN: u64 = 2;

// ---- Custom errors ----

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum GenesisError {
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum InflationError {
    #[error("Error in calculating rewards: {0}")]
    Rewards(rewards::RewardsError),
    #[error("Expected validator {0} to be in consensus set but got: {1:?}")]
    ExpectedValidatorInConsensus(Address, Option<ValidatorState>),
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
    UnbondAmountGreaterThanBond(String, String),
    #[error("No bonds found for the validator {0}")]
    ValidatorHasNoBonds(Address),
    #[error("Voting power not found for the validator {0}")]
    ValidatorHasNoVotingPower(Address),
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
    #[error("Trying to unbond from a frozen validator: {0}")]
    ValidatorIsFrozen(Address),
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
    NegativeRate(Dec, Address),
    #[error("Rate change of {0} is too large for validator {1}")]
    RateChangeTooLarge(Dec, Address),
    #[error(
        "There is no maximum rate change written in storage for validator {0}"
    )]
    NoMaxSetInStorage(Address),
    #[error("Cannot write to storage for validator {0}")]
    CannotWrite(Address),
    #[error("Cannot read storage for validator {0}")]
    CannotRead(Address),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum UnjailValidatorError {
    #[error("The given address {0} is not a validator address")]
    NotAValidator(Address),
    #[error("The given address {0} is not jailed in epoch {1}")]
    NotJailed(Address, Epoch),
    #[error(
        "The given address {0} is not eligible for unnjailing until epoch \
         {1}: current epoch is {2}"
    )]
    NotEligible(Address, Epoch, Epoch),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum RedelegationError {
    #[error("The redelegation is chained")]
    IsChainedRedelegation,
}

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

impl From<InflationError> for storage_api::Error {
    fn from(err: InflationError) -> Self {
        Self::new(err)
    }
}

impl From<UnjailValidatorError> for storage_api::Error {
    fn from(err: UnjailValidatorError) -> Self {
        Self::new(err)
    }
}

impl From<RedelegationError> for storage_api::Error {
    fn from(err: RedelegationError) -> Self {
        Self::new(err)
    }
}

// ---- Storage handles ----

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

/// Get the storage handle to a PoS validator's eth hot key.
pub fn validator_eth_hot_key_handle(
    validator: &Address,
) -> ValidatorEthHotKeys {
    let key = storage::validator_eth_hot_key_key(validator);
    ValidatorEthHotKeys::open(key)
}

/// Get the storage handle to a PoS validator's eth cold key.
pub fn validator_eth_cold_key_handle(
    validator: &Address,
) -> ValidatorEthColdKeys {
    let key = storage::validator_eth_cold_key_key(validator);
    ValidatorEthColdKeys::open(key)
}

/// Get the storage handle to the total consensus validator stake
pub fn total_consensus_stake_key_handle() -> TotalConsensusStakes {
    let key = storage::total_consensus_stake_key();
    TotalConsensusStakes::open(key)
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

/// Get the storage handle to the set of all validators
pub fn validator_addresses_handle() -> ValidatorAddresses {
    let key = storage::validator_addresses_key();
    ValidatorAddresses::open(key)
}

/// Get the storage handle to a PoS validator's commission rate
pub fn validator_commission_rate_handle(
    validator: &Address,
) -> CommissionRates {
    let key = storage::validator_commission_rate_key(validator);
    CommissionRates::open(key)
}

/// Get the storage handle to a bond
pub fn bond_handle(source: &Address, validator: &Address) -> Bonds {
    let bond_id = BondId {
        source: source.clone(),
        validator: validator.clone(),
    };
    let key = storage::bond_key(&bond_id);
    Bonds::open(key)
}

/// Get the storage handle to a validator's total bonds
pub fn total_bonded_handle(validator: &Address) -> Bonds {
    let key = storage::validator_total_bonded_key(validator);
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

/// Get the storage handle to a validator's total-unbonded map
pub fn unbond_records_handle(validator: &Address) -> ValidatorUnbondRecords {
    let key = storage::validator_total_unbonded_key(validator);
    ValidatorUnbondRecords::open(key)
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

/// Get the storage handle to list of all slashes to be processed and ultimately
/// placed in the `validator_slashes_handle`
pub fn enqueued_slashes_handle() -> EpochedSlashes {
    let key = storage::enqueued_slashes_key();
    EpochedSlashes::open(key)
}

/// Get the storage handle to the rewards accumulator for the consensus
/// validators in a given epoch
pub fn rewards_accumulator_handle() -> RewardsAccumulator {
    let key = storage::consensus_validator_rewards_accumulator_key();
    RewardsAccumulator::open(key)
}

/// Get the storage handle to a validator's self rewards products
pub fn validator_rewards_products_handle(
    validator: &Address,
) -> RewardsProducts {
    let key = storage::validator_self_rewards_product_key(validator);
    RewardsProducts::open(key)
}

/// Get the storage handle to the delegator rewards products associated with a
/// particular validator
pub fn delegator_rewards_products_handle(
    validator: &Address,
) -> RewardsProducts {
    let key = storage::validator_delegation_rewards_product_key(validator);
    RewardsProducts::open(key)
}

/// Get the storage handle to a validator's incoming redelegations
pub fn validator_incoming_redelegations_handle(
    validator: &Address,
) -> IncomingRedelegations {
    let key = storage::validator_incoming_redelegations_key(validator);
    IncomingRedelegations::open(key)
}

/// Get the storage handle to a validator's outgoing redelegations
pub fn validator_outgoing_redelegations_handle(
    validator: &Address,
) -> OutgoingRedelegations {
    let key: Key = storage::validator_outgoing_redelegations_key(validator);
    OutgoingRedelegations::open(key)
}

/// Get the storage handle to a validator's total redelegated bonds
pub fn validator_total_redelegated_bonded_handle(
    validator: &Address,
) -> TotalRedelegatedBonded {
    let key: Key = storage::validator_total_redelegated_bonded_key(validator);
    TotalRedelegatedBonded::open(key)
}

/// Get the storage handle to a validator's outgoing redelegations
pub fn validator_total_redelegated_unbonded_handle(
    validator: &Address,
) -> TotalRedelegatedUnbonded {
    let key: Key = storage::validator_total_redelegated_unbonded_key(validator);
    TotalRedelegatedUnbonded::open(key)
}

/// Get the storage handle to a delegator's redelegated bonds information
pub fn delegator_redelegated_bonds_handle(
    delegator: &Address,
) -> DelegatorRedelegatedBonded {
    let key: Key = storage::delegator_redelegated_bonds_key(delegator);
    DelegatorRedelegatedBonded::open(key)
}

/// Get the storage handle to a delegator's redelegated unbonds information
pub fn delegator_redelegated_unbonds_handle(
    delegator: &Address,
) -> DelegatorRedelegatedUnbonded {
    let key: Key = storage::delegator_redelegated_unbonds_key(delegator);
    DelegatorRedelegatedUnbonded::open(key)
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
    validator_addresses_handle().init(storage, current_epoch)?;

    for GenesisValidator {
        address,
        tokens,
        consensus_key,
        eth_cold_key,
        eth_hot_key,
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

        validator_addresses_handle()
            .at(&current_epoch)
            .insert(storage, address.clone())?;

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
        validator_eth_hot_key_handle(&address).init_at_genesis(
            storage,
            eth_hot_key,
            current_epoch,
        )?;
        validator_eth_cold_key_handle(&address).init_at_genesis(
            storage,
            eth_cold_key,
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
        total_bonded_handle(&address).init_at_genesis(
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

    // Store the total consensus validator stake to storage
    store_total_consensus_stake(storage, current_epoch)?;

    // Write total deltas to storage
    total_deltas_handle().init_at_genesis(
        storage,
        token::Change::from(total_bonded),
        current_epoch,
    )?;

    // Credit bonded token amount to the PoS account
    let staking_token = staking_token_address(storage);
    credit_tokens(storage, &staking_token, &ADDRESS, total_bonded)?;
    // Copy the genesis validator set into the pipeline epoch as well
    for epoch in (current_epoch.next()).iter_range(params.pipeline_len) {
        copy_validator_sets_and_positions(storage, current_epoch, epoch)?;
    }

    tracing::debug!("Genesis initialized");

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
) -> storage_api::Result<Option<Dec>>
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
    change: Dec,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = validator_max_commission_rate_change_key(validator);
    storage.write(&key, change)
}

/// Read the most recent slash epoch for the given epoch
pub fn read_validator_last_slash_epoch<S>(
    storage: &S,
    validator: &Address,
) -> storage_api::Result<Option<Epoch>>
where
    S: StorageRead,
{
    let key = validator_last_slash_key(validator);
    storage.read(&key)
}

/// Write the most recent slash epoch for the given epoch
pub fn write_validator_last_slash_epoch<S>(
    storage: &mut S,
    validator: &Address,
    epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = validator_last_slash_key(validator);
    storage.write(&key, epoch)
}

/// Read last block proposer address.
pub fn read_last_block_proposer_address<S>(
    storage: &S,
) -> storage_api::Result<Option<Address>>
where
    S: StorageRead,
{
    let key = last_block_proposer_key();
    storage.read(&key)
}

/// Write last block proposer address.
pub fn write_last_block_proposer_address<S>(
    storage: &mut S,
    address: Address,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = last_block_proposer_key();
    storage.write(&key, address)
}

/// Read PoS validator's delta value.
pub fn read_validator_deltas_value<S>(
    storage: &S,
    validator: &Address,
    epoch: &namada_core::types::storage::Epoch,
) -> storage_api::Result<Option<token::Change>>
where
    S: StorageRead,
{
    let handle = validator_deltas_handle(validator);
    handle.get_delta_val(storage, *epoch)
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
    let handle = validator_deltas_handle(validator);
    let amount = handle
        .get_sum(storage, epoch, params)?
        .map(token::Amount::from_change);
    Ok(amount)
}

/// Add or remove PoS validator's stake delta value
pub fn update_validator_deltas<S>(
    storage: &mut S,
    validator: &Address,
    delta: token::Change,
    current_epoch: namada_core::types::storage::Epoch,
    offset: u64,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let handle = validator_deltas_handle(validator);
    let val = handle
        .get_delta_val(storage, current_epoch + offset)?
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

/// Read all addresses from the below-threshold set
pub fn read_below_threshold_validator_set_addresses<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<HashSet<Address>>
where
    S: StorageRead,
{
    let params = read_pos_params(storage)?;
    Ok(validator_addresses_handle()
        .at(&epoch)
        .iter(storage)?
        .map(Result::unwrap)
        .filter(|address| {
            matches!(
                validator_state_handle(address).get(storage, epoch, &params),
                Ok(Some(ValidatorState::BelowThreshold))
            )
        })
        .collect())
}

/// Read all addresses from consensus validator set with their stake.
pub fn read_consensus_validator_set_addresses_with_stake<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<BTreeSet<WeightedValidator>>
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

/// Count the number of consensus validators
pub fn get_num_consensus_validators<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<u64>
where
    S: StorageRead,
{
    Ok(consensus_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .count() as u64)
}

/// Read all addresses from below-capacity validator set with their stake.
pub fn read_below_capacity_validator_set_addresses_with_stake<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<BTreeSet<WeightedValidator>>
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
/// TODO: expand this to include the jailed validators as well, as it currently
/// only does consensus and bc
pub fn read_all_validator_addresses<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<HashSet<Address>>
where
    S: StorageRead,
{
    validator_addresses_handle()
        .at(&epoch)
        .iter(storage)?
        .collect()
}

/// Update PoS total deltas.
/// Note: for EpochedDelta, write the value to change storage by
pub fn update_total_deltas<S>(
    storage: &mut S,
    delta: token::Change,
    current_epoch: namada_core::types::storage::Epoch,
    offset: u64,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let handle = total_deltas_handle();
    let val = handle
        .get_delta_val(storage, current_epoch + offset)?
        .unwrap_or_default();
    handle.set(storage, val + delta, current_epoch, offset)
}

/// Check if the provided address is a validator address
pub fn is_validator<S>(
    storage: &S,
    address: &Address,
) -> storage_api::Result<bool>
where
    S: StorageRead + StorageWrite,
{
    let rate = read_validator_max_commission_rate_change(storage, address)?;
    Ok(rate.is_some())
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
    tracing::debug!(
        "Bonding token amount {} at epoch {current_epoch}",
        amount.to_string_native()
    );
    let params = read_pos_params(storage)?;
    let pipeline_epoch = current_epoch + params.pipeline_len;
    if let Some(source) = source {
        if source != validator && is_validator(storage, source)? {
            return Err(
                BondError::SourceMustNotBeAValidator(source.clone()).into()
            );
        }
    }
    let validator_state_handle = validator_state_handle(validator);
    let state = validator_state_handle.get(storage, pipeline_epoch, &params)?;
    if state.is_none() {
        return Err(BondError::NotAValidator(validator.clone()).into());
    }

    let source = source.unwrap_or(validator);
    tracing::debug!("Source {} --> Validator {}", source, validator);
    let bond_handle = bond_handle(source, validator);
    let total_bonded_handle = total_bonded_handle(validator);

    // Check that validator is not inactive at anywhere between the current
    // epoch and pipeline offset
    for epoch in current_epoch.iter_range(params.pipeline_len) {
        if let Some(ValidatorState::Inactive) =
            validator_state_handle.get(storage, epoch, &params)?
        {
            return Err(BondError::InactiveValidator(validator.clone()).into());
        }
    }

    tracing::debug!("\nBonds before incrementing:");
    for ep in Epoch::default().iter_range(current_epoch.0 + 3) {
        let delta = bond_handle.get_delta_val(storage, ep)?.unwrap_or_default();
        if !delta.is_zero() {
            tracing::debug!(
                "bond ∆ at epoch {}: {}",
                ep,
                delta.to_string_native()
            );
        }
    }

    // Initialize or update the bond at the pipeline offset
    let offset = params.pipeline_len;
    let cur_remain = bond_handle
        .get_delta_val(storage, current_epoch + offset)?
        .unwrap_or_default();
    bond_handle.set(storage, cur_remain + amount, current_epoch, offset)?;
    let cur_remain_global = total_bonded_handle
        .get_delta_val(storage, current_epoch + offset)?
        .unwrap_or_default();
    total_bonded_handle.set(
        storage,
        cur_remain_global + amount,
        current_epoch,
        offset,
    )?;

    tracing::debug!("\nBonds after incrementing:");
    for ep in Epoch::default().iter_range(current_epoch.0 + 3) {
        let delta = bond_handle.get_delta_val(storage, ep)?.unwrap_or_default();
        if !delta.is_zero() {
            tracing::debug!(
                "bond ∆ at epoch {}: {}",
                ep,
                delta.to_string_native()
            );
        }
    }

    // Update the validator set
    // We allow bonding if the validator is jailed, however if jailed, there
    // must be no changes to the validator set. Check at the pipeline epoch.
    let is_jailed_at_pipeline = matches!(
        validator_state_handle
            .get(storage, pipeline_epoch, &params)?
            .unwrap(),
        ValidatorState::Jailed
    );
    if !is_jailed_at_pipeline {
        update_validator_set(
            storage,
            &params,
            validator,
            amount,
            current_epoch,
        )?;
    }

    // Update the validator and total deltas
    update_validator_deltas(storage, validator, amount, current_epoch, offset)?;

    update_total_deltas(storage, amount, current_epoch, offset)?;

    // Transfer the bonded tokens from the source to PoS
    let staking_token = staking_token_address(storage);
    transfer_tokens(
        storage,
        &staking_token,
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
    let consensus_set = consensus_validator_set_handle().at(&target_epoch);
    let below_cap_set = below_capacity_validator_set_handle().at(&target_epoch);

    let num_consensus_validators =
        get_num_consensus_validators(storage, target_epoch)?;

    if stake < params.validator_stake_threshold {
        validator_state_handle(address).set(
            storage,
            ValidatorState::BelowThreshold,
            current_epoch,
            offset,
        )?;
    } else if num_consensus_validators < params.max_validator_slots {
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
    } else {
        // Check to see if the current genesis validator should replace one
        // already in the consensus set
        let min_consensus_amount =
            get_min_consensus_validator_amount(&consensus_set, storage)?;
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
            // Update and set the validator states
            validator_state_handle(address).set(
                storage,
                ValidatorState::Consensus,
                current_epoch,
                offset,
            )?;
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

/// Update validator set at the pipeline epoch when a validator receives a new
/// bond and when its bond is unbonded (self-bond or delegation).
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
    if token_change.is_zero() {
        return Ok(());
    }
    let pipeline_epoch = current_epoch + params.pipeline_len;
    tracing::debug!(
        "Update epoch for validator set: {pipeline_epoch}, validator: \
         {validator}"
    );
    let consensus_validator_set = consensus_validator_set_handle();
    let below_capacity_validator_set = below_capacity_validator_set_handle();

    // Validator sets at the pipeline offset
    let consensus_val_handle = consensus_validator_set.at(&pipeline_epoch);
    let below_capacity_val_handle =
        below_capacity_validator_set.at(&pipeline_epoch);

    let tokens_pre =
        read_validator_stake(storage, params, validator, pipeline_epoch)?
            .unwrap_or_default();

    // tracing::debug!("VALIDATOR STAKE BEFORE UPDATE: {}", tokens_pre);

    let tokens_post = tokens_pre.change() + token_change;
    let tokens_post = token::Amount::from_change(tokens_post);

    // If token amounts both before and after the action are below the threshold
    // stake, do nothing
    if tokens_pre < params.validator_stake_threshold
        && tokens_post < params.validator_stake_threshold
    {
        return Ok(());
    }

    // The position is only set when the validator is in consensus or
    // below_capacity set (not in below_threshold set)
    let position = read_validator_set_position(
        storage,
        validator,
        pipeline_epoch,
        params,
    )?;
    if let Some(position) = position {
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

            // First remove the consensus validator
            consensus_vals_pre.remove(storage, &position)?;

            let max_below_capacity_validator_amount =
                get_max_below_capacity_validator_amount(
                    &below_capacity_val_handle,
                    storage,
                )?
                .unwrap_or_default();

            if tokens_post < params.validator_stake_threshold {
                tracing::debug!(
                    "Demoting this validator to the below-threshold set"
                );
                // Set the validator state as below-threshold
                validator_state_handle(validator).set(
                    storage,
                    ValidatorState::BelowThreshold,
                    current_epoch,
                    params.pipeline_len,
                )?;

                // Remove the validator's position from storage
                validator_set_positions_handle()
                    .at(&pipeline_epoch)
                    .remove(storage, validator)?;

                // Promote the next below-cap validator if there is one
                if let Some(max_bc_amount) =
                    get_max_below_capacity_validator_amount(
                        &below_capacity_val_handle,
                        storage,
                    )?
                {
                    // Remove the max below-capacity validator first
                    let below_capacity_vals_max =
                        below_capacity_val_handle.at(&max_bc_amount.into());
                    let lowest_position =
                        find_first_position(&below_capacity_vals_max, storage)?
                            .unwrap();
                    let removed_max_below_capacity = below_capacity_vals_max
                        .remove(storage, &lowest_position)?
                        .expect("Must have been removed");

                    // Insert the previous max below-capacity validator into the
                    // consensus set
                    insert_validator_into_set(
                        &consensus_val_handle.at(&max_bc_amount),
                        storage,
                        &pipeline_epoch,
                        &removed_max_below_capacity,
                    )?;
                    validator_state_handle(&removed_max_below_capacity).set(
                        storage,
                        ValidatorState::Consensus,
                        current_epoch,
                        params.pipeline_len,
                    )?;
                }
            } else if tokens_post < max_below_capacity_validator_amount {
                tracing::debug!(
                    "Demoting this validator to the below-capacity set and \
                     promoting another to the consensus set"
                );
                // Place the validator into the below-capacity set and promote
                // the lowest position max below-capacity
                // validator.

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
                    &consensus_val_handle
                        .at(&max_below_capacity_validator_amount),
                    storage,
                    &pipeline_epoch,
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
                    &pipeline_epoch,
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
                // The current validator should remain in the consensus set -
                // place it into a new position
                insert_validator_into_set(
                    &consensus_val_handle.at(&tokens_post),
                    storage,
                    &pipeline_epoch,
                    validator,
                )?;
            }
        } else {
            // It's initially below-capacity
            tracing::debug!("Target validator is below-capacity");

            let below_capacity_vals_pre =
                below_capacity_val_handle.at(&tokens_pre.into());
            let removed = below_capacity_vals_pre.remove(storage, &position)?;
            debug_assert!(removed.is_some());
            debug_assert_eq!(&removed.unwrap(), validator);

            let min_consensus_validator_amount =
                get_min_consensus_validator_amount(
                    &consensus_val_handle,
                    storage,
                )?;

            if tokens_post > min_consensus_validator_amount {
                // Place the validator into the consensus set and demote the
                // last position min consensus validator to the
                // below-capacity set
                tracing::debug!(
                    "Inserting validator into the consensus set and demoting \
                     a consensus validator to the below-capacity set"
                );

                insert_into_consensus_and_demote_to_below_cap(
                    storage,
                    params,
                    validator,
                    tokens_post,
                    min_consensus_validator_amount,
                    current_epoch,
                    &consensus_val_handle,
                    &below_capacity_val_handle,
                )?;
            } else if tokens_post >= params.validator_stake_threshold {
                tracing::debug!("Validator remains in below-capacity set");
                // The current validator should remain in the below-capacity set
                insert_validator_into_set(
                    &below_capacity_val_handle.at(&tokens_post.into()),
                    storage,
                    &pipeline_epoch,
                    validator,
                )?;
                validator_state_handle(validator).set(
                    storage,
                    ValidatorState::BelowCapacity,
                    current_epoch,
                    params.pipeline_len,
                )?;
            } else {
                // The current validator is demoted to the below-threshold set
                tracing::debug!(
                    "Demoting this validator to the below-threshold set"
                );

                validator_state_handle(validator).set(
                    storage,
                    ValidatorState::BelowThreshold,
                    current_epoch,
                    params.pipeline_len,
                )?;

                // Remove the validator's position from storage
                validator_set_positions_handle()
                    .at(&pipeline_epoch)
                    .remove(storage, validator)?;
            }
        }
    } else {
        // If there is no position at pipeline offset, then the validator must
        // be in the below-threshold set
        debug_assert!(tokens_pre < params.validator_stake_threshold);
        tracing::debug!("Target validator is below-threshold");

        // Move the validator into the appropriate set
        let num_consensus_validators =
            get_num_consensus_validators(storage, pipeline_epoch)?;
        if num_consensus_validators < params.max_validator_slots {
            // Just insert into the consensus set
            tracing::debug!("Inserting validator into the consensus set");

            insert_validator_into_set(
                &consensus_val_handle.at(&tokens_post),
                storage,
                &pipeline_epoch,
                validator,
            )?;
            validator_state_handle(validator).set(
                storage,
                ValidatorState::Consensus,
                current_epoch,
                params.pipeline_len,
            )?;
        } else {
            let min_consensus_validator_amount =
                get_min_consensus_validator_amount(
                    &consensus_val_handle,
                    storage,
                )?;
            if tokens_post > min_consensus_validator_amount {
                // Insert this validator into consensus and demote one into the
                // below-capacity
                tracing::debug!(
                    "Inserting validator into the consensus set and demoting \
                     a consensus validator to the below-capacity set"
                );

                insert_into_consensus_and_demote_to_below_cap(
                    storage,
                    params,
                    validator,
                    tokens_post,
                    min_consensus_validator_amount,
                    current_epoch,
                    &consensus_val_handle,
                    &below_capacity_val_handle,
                )?;
            } else {
                // Insert this validator into below-capacity
                tracing::debug!(
                    "Inserting validator into the below-capacity set"
                );

                insert_validator_into_set(
                    &below_capacity_val_handle.at(&tokens_post.into()),
                    storage,
                    &pipeline_epoch,
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
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_into_consensus_and_demote_to_below_cap<S>(
    storage: &mut S,
    params: &PosParams,
    validator: &Address,
    tokens_post: token::Amount,
    min_consensus_amount: token::Amount,
    current_epoch: Epoch,
    consensus_set: &ConsensusValidatorSet,
    below_capacity_set: &BelowCapacityValidatorSet,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    // First, remove the last position min consensus validator
    let consensus_vals_min = consensus_set.at(&min_consensus_amount);
    let last_position_of_min_consensus_vals =
        find_last_position(&consensus_vals_min, storage)?
            .expect("There must be always be at least 1 consensus validator");
    let removed_min_consensus = consensus_vals_min
        .remove(storage, &last_position_of_min_consensus_vals)?
        .expect("There must be always be at least 1 consensus validator");

    let pipeline_epoch = current_epoch + params.pipeline_len;

    // Insert the min consensus validator into the below-capacity
    // set
    insert_validator_into_set(
        &below_capacity_set.at(&min_consensus_amount.into()),
        storage,
        &pipeline_epoch,
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
        &consensus_set.at(&tokens_post),
        storage,
        &pipeline_epoch,
        validator,
    )?;
    validator_state_handle(validator).set(
        storage,
        ValidatorState::Consensus,
        current_epoch,
        params.pipeline_len,
    )?;
    Ok(())
}

/// Validator sets and positions copying into a future epoch
pub fn copy_validator_sets_and_positions<S>(
    storage: &mut S,
    current_epoch: Epoch,
    target_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let prev_epoch = target_epoch.prev();

    let consensus_validator_set = consensus_validator_set_handle();
    let below_capacity_validator_set = below_capacity_validator_set_handle();

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
    let validator_set_positions_handle = validator_set_positions_handle();
    let positions_handle = validator_set_positions_handle.at(&prev_epoch);

    for result in positions_handle.iter(storage)? {
        let (validator, position) = result?;
        positions.insert(validator, position);
    }

    let new_positions_handle = validator_set_positions_handle.at(&target_epoch);
    for (validator, position) in positions {
        let prev = new_positions_handle.insert(storage, validator, position)?;
        debug_assert!(prev.is_none());
    }
    validator_set_positions_handle.set_last_update(storage, current_epoch)?;

    // Copy set of all validator addresses
    let mut all_validators = HashSet::<Address>::default();
    let validator_addresses_handle = validator_addresses_handle();
    let all_validators_handle = validator_addresses_handle.at(&prev_epoch);
    for result in all_validators_handle.iter(storage)? {
        let validator = result?;
        all_validators.insert(validator);
    }
    let new_all_validators_handle =
        validator_addresses_handle.at(&target_epoch);
    for validator in all_validators {
        let was_in = new_all_validators_handle.insert(storage, validator)?;
        debug_assert!(!was_in);
    }

    Ok(())
}

/// Compute total validator stake for the current epoch
fn compute_total_consensus_stake<S>(
    storage: &S,
    epoch: Epoch,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    consensus_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .fold(Ok(token::Amount::zero()), |acc, entry| {
            let acc = acc?;
            let (
                NestedSubKey::Data {
                    key: amount,
                    nested_sub_key: _,
                },
                _validator,
            ) = entry?;
            Ok(acc + amount)
        })
}

/// Store total consensus stake
pub fn store_total_consensus_stake<S>(
    storage: &mut S,
    epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let total = compute_total_consensus_stake(storage, epoch)?;
    tracing::debug!(
        "Computed total consensus stake for epoch {}: {}",
        epoch,
        total.to_string_native()
    );
    total_consensus_stake_key_handle().set(storage, total, epoch, 0)
}

/// Purge the validator sets from the epochs older than the current epoch minus
/// `STORE_VALIDATOR_SETS_LEN`
pub fn purge_validator_sets_for_old_epoch<S>(
    storage: &mut S,
    epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    if Epoch(STORE_VALIDATOR_SETS_LEN) < epoch {
        let old_epoch = epoch - STORE_VALIDATOR_SETS_LEN - 1;
        consensus_validator_set_handle()
            .get_data_handler()
            .remove_all(storage, &old_epoch)?;
        below_capacity_validator_set_handle()
            .get_data_handler()
            .remove_all(storage, &old_epoch)?;
    }
    Ok(())
}

/// Read the position of the validator in the subset of validators that have the
/// same bonded stake. This information is held in its own epoched structure in
/// addition to being inside the validator sets.
fn read_validator_set_position<S>(
    storage: &S,
    validator: &Address,
    epoch: Epoch,
    _params: &PosParams,
) -> storage_api::Result<Option<Position>>
where
    S: StorageRead,
{
    let handle = validator_set_positions_handle();
    // handle.get_position(storage, &epoch, validator, params)
    handle.get_data_handler().at(&epoch).get(storage, validator)
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

/// Returns `Ok(None)` when the below capacity set is empty.
fn get_max_below_capacity_validator_amount<S>(
    handle: &BelowCapacityValidatorSet,
    storage: &S,
) -> storage_api::Result<Option<token::Amount>>
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
            } => token::Amount::from(key),
        }))
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

/// Used below in `fn unbond_tokens` to update the bond and unbond amounts
#[derive(Eq, Hash, PartialEq)]
struct BondAndUnbondUpdates {
    bond_start: Epoch,
    new_bond_value: token::Change,
    unbond_value: token::Change,
}

/// Unbond tokens that are bonded between a validator and a source (self or
/// delegator)
pub fn unbond_tokens_old<S>(
    storage: &mut S,
    source: Option<&Address>,
    validator: &Address,
    amount: token::Amount,
    current_epoch: Epoch,
    _is_redelegation: bool,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let amount = amount.change();
    tracing::debug!(
        "Unbonding token amount {} at epoch {current_epoch}",
        amount.to_string_native()
    );
    let params = read_pos_params(storage)?;
    let pipeline_epoch = current_epoch + params.pipeline_len;

    // Make sure source is not some other validator
    if let Some(source) = source {
        if source != validator && is_validator(storage, source)? {
            return Err(
                BondError::SourceMustNotBeAValidator(source.clone()).into()
            );
        }
    }
    // Make sure the target is actually a validator
    if !is_validator(storage, validator)? {
        return Err(BondError::NotAValidator(validator.clone()).into());
    }
    // Make sure the validator is not currently frozen
    if is_validator_frozen(storage, validator, current_epoch, &params)? {
        return Err(UnbondError::ValidatorIsFrozen(validator.clone()).into());
    }

    // Should be able to unbond inactive validators

    // Check that validator is not inactive at anywhere between the current
    // epoch and pipeline offset
    // let validator_state_handle = validator_state_handle(validator);
    // for epoch in current_epoch.iter_range(params.pipeline_len) {
    //     if let Some(ValidatorState::Inactive) =
    //         validator_state_handle.get(storage, epoch, &params)?
    //     {
    //         return
    // Err(BondError::InactiveValidator(validator.clone()).into());     }
    // }

    let source = source.unwrap_or(validator);
    let bonds_handle = bond_handle(source, validator);

    tracing::debug!("\nBonds before decrementing:");
    for ep in Epoch::default().iter_range(current_epoch.0 + 3) {
        let delta =
            bonds_handle.get_delta_val(storage, ep)?.unwrap_or_default();
        if !delta.is_zero() {
            tracing::debug!(
                "bond ∆ at epoch {}: {}",
                ep,
                delta.to_string_native()
            );
        }
    }

    // Make sure there are enough tokens left in the bond at the pipeline offset
    let remaining_at_pipeline = bonds_handle
        .get_sum(storage, pipeline_epoch, &params)?
        .unwrap_or_default();
    if amount > remaining_at_pipeline {
        return Err(UnbondError::UnbondAmountGreaterThanBond(
            token::Amount::from_change(amount).to_string_native(),
            token::Amount::from_change(remaining_at_pipeline)
                .to_string_native(),
        )
        .into());
    }

    let unbonds = unbond_handle(source, validator);
    let withdrawable_epoch = current_epoch + params.withdrawable_epoch_offset();

    let mut remaining = amount;
    let mut amount_after_slashing = token::Change::default();

    // Iterate thru bonds, find non-zero delta entries starting from
    // future-most, then decrement those values. For every value that
    // gets decremented down to 0, need a unique unbond object.
    // Read all matched bonds into memory to do reverse iteration
    #[allow(clippy::needless_collect)]
    let bonds: Vec<Result<_, _>> =
        bonds_handle.get_data_handler().iter(storage)?.collect();

    let mut bond_iter = bonds.into_iter().rev();
    let mut new_bond_values = HashSet::<BondAndUnbondUpdates>::new();

    while remaining > token::Change::default() {
        let bond = bond_iter.next().transpose()?;
        if bond.is_none() {
            continue;
        }
        let (bond_epoch, bond_amount) = bond.unwrap();
        // println!("\nBond (epoch, amnt) = ({}, {})", bond_epoch, bond_amount);
        // println!("remaining = {}", remaining);

        let to_unbond = cmp::min(bond_amount, remaining);
        new_bond_values.insert(BondAndUnbondUpdates {
            bond_start: bond_epoch,
            new_bond_value: bond_amount - to_unbond,
            unbond_value: to_unbond,
        });
        // println!("to_unbond (init) = {}", to_unbond);

        let slashes_for_this_bond =
            find_slashes_in_range(storage, bond_epoch, None, validator)?;

        amount_after_slashing += get_slashed_amount(
            &params,
            token::Amount::from_change(to_unbond),
            &slashes_for_this_bond,
        )?;
        // println!("Cur amnt after slashing = {}", &amount_after_slashing);

        // Update the unbond records
        let cur_amnt = unbond_records_handle(validator)
            .at(&pipeline_epoch)
            .get(storage, &bond_epoch)?
            .unwrap_or_default();
        unbond_records_handle(validator)
            .at(&pipeline_epoch)
            .insert(
                storage,
                bond_epoch,
                cur_amnt + token::Amount::from_change(to_unbond),
            )?;

        remaining -= to_unbond;
    }
    drop(bond_iter);

    // Write the in-memory bond and unbond values back to storage
    for BondAndUnbondUpdates {
        bond_start,
        new_bond_value,
        unbond_value,
    } in new_bond_values.into_iter()
    {
        bonds_handle.set(storage, new_bond_value, bond_start, 0)?;
        update_unbond(
            &unbonds,
            storage,
            &withdrawable_epoch,
            &bond_start,
            token::Amount::from_change(unbond_value),
        )?;
    }

    tracing::debug!("Bonds after decrementing:");
    for ep in Epoch::default().iter_range(current_epoch.0 + 3) {
        let delta =
            bonds_handle.get_delta_val(storage, ep)?.unwrap_or_default();
        if !delta.is_zero() {
            tracing::debug!(
                "bond ∆ at epoch {}: {}",
                ep,
                delta.to_string_native()
            );
        }
    }
    tracing::debug!(
        "Token change including slashes on unbond = {}",
        (-amount_after_slashing).to_string_native()
    );

    // Update the validator set at the pipeline offset. Since unbonding from a
    // jailed validator who is no longer frozen is allowed, only update the
    // validator set if the validator is not jailed
    let is_jailed_at_pipeline = matches!(
        validator_state_handle(validator)
            .get(storage, pipeline_epoch, &params)?
            .unwrap(),
        ValidatorState::Jailed
    );
    if !is_jailed_at_pipeline {
        update_validator_set(
            storage,
            &params,
            validator,
            -amount_after_slashing,
            current_epoch,
        )?;
    }

    // Update the validator and total deltas at the pipeline offset
    update_validator_deltas(
        storage,
        validator,
        -amount_after_slashing,
        current_epoch,
        params.pipeline_len,
    )?;
    update_total_deltas(
        storage,
        -amount_after_slashing,
        current_epoch,
        params.pipeline_len,
    )?;

    Ok(())
}

/// Temp: In quint this is from `ResultUnbondTx` field `resultSlashing: {sum:
/// int, epochMap: Epoch -> int}`
#[derive(Debug, Default)]
pub struct ResultSlashing {
    /// The token amount unbonded from the validator stake after accounting for
    /// slashes
    pub sum: token::Amount,
    /// TODO
    pub epoch_map: BTreeMap<Epoch, token::Amount>,
}

/// Unbond tokens that are bonded between a validator and a source (self or
/// delegator)
pub fn unbond_tokens<S>(
    storage: &mut S,
    source: Option<&Address>,
    validator: &Address,
    amount: token::Amount,
    current_epoch: Epoch,
    is_redelegation: bool,
) -> storage_api::Result<ResultSlashing>
where
    S: StorageRead + StorageWrite,
{
    let amount = amount.change();
    tracing::debug!("Unbonding token amount {amount} at epoch {current_epoch}");
    let params = read_pos_params(storage)?;
    let pipeline_epoch = current_epoch + params.pipeline_len;

    // Make sure source is not some other validator
    if let Some(source) = source {
        if source != validator && is_validator(storage, source)? {
            return Err(
                BondError::SourceMustNotBeAValidator(source.clone()).into()
            );
        }
    }
    // Make sure the target is actually a validator
    if !is_validator(storage, validator)? {
        return Err(BondError::NotAValidator(validator.clone()).into());
    }
    // Make sure the validator is not currently frozen
    if is_validator_frozen(storage, validator, current_epoch, &params)? {
        return Err(UnbondError::ValidatorIsFrozen(validator.clone()).into());
    }

    // TODO: check that validator is not inactive (when implemented)!

    let source = source.unwrap_or(validator);
    let bonds_handle = bond_handle(source, validator);

    // TODO: only do this iteration of tracing::debug is enabled
    // Check this !!!!
    if env::var("RUST_LOG") == Ok(String::from("debug")) {
        tracing::debug!("\nBonds before decrementing:");
        for ep in Epoch::default().iter_range(current_epoch.0 + 3) {
            let delta =
                bonds_handle.get_delta_val(storage, ep)?.unwrap_or_default();
            if !delta.is_zero() {
                tracing::debug!("bond ∆ at epoch {}: {}", ep, delta);
            }
        }
    }

    // Make sure there are enough tokens left in the bond at the pipeline offset
    let remaining_at_pipeline = bonds_handle
        .get_sum(storage, pipeline_epoch, &params)?
        .unwrap_or_default();
    if amount > remaining_at_pipeline {
        return Err(UnbondError::UnbondAmountGreaterThanBond(
            token::Amount::from_change(amount).to_string_native(),
            token::Amount::from_change(remaining_at_pipeline)
                .to_string_native(),
        )
        .into());
    }

    let unbonds = unbond_handle(source, validator);
    let withdrawable_epoch = current_epoch + params.withdrawable_epoch_offset();

    let redelegated_bonds =
        delegator_redelegated_bonds_handle(source).at(validator);

    // `resultUnbonding`
    let bonds_to_unbond = find_bonds_to_remove(
        storage,
        &bonds_handle.get_data_handler(),
        amount,
    )?;

    if env::var("RUST_LOG") == Ok(String::from("debug")) {
        tracing::debug!("\nBonds after decrementing:");
        for ep in Epoch::default().iter_range(current_epoch.0 + 3) {
            let delta =
                bonds_handle.get_delta_val(storage, ep)?.unwrap_or_default();
            if !delta.is_zero() {
                tracing::debug!("bond ∆ at epoch {}: {}", ep, delta);
            }
        }
    }

    // `modifiedRedelegation`
    let modified_redelegation = match bonds_to_unbond.new_entry {
        Some((bond_epoch, new_bond_amount)) => {
            if redelegated_bonds.contains(storage, &bond_epoch)? {
                compute_modified_redelegation(
                    storage,
                    &redelegated_bonds.at(&bond_epoch),
                    bond_epoch,
                    new_bond_amount,
                )?
            } else {
                ModifiedRedelegation::default()
            }
        }
        None => ModifiedRedelegation::default(),
    };

    // `updatedRedelegatedBonded`
    if let Some(epoch) = modified_redelegation.epoch {
        // First remove redelegation entries corresponding the outer epoch key
        for epoch_to_remove in &bonds_to_unbond.epochs {
            redelegated_bonds.remove_all(storage, epoch_to_remove)?;
        }
        // Then updated the redelegated bonds at this epoch
        let rbonds = redelegated_bonds.at(&epoch);
        update_redelegated_bonds(storage, &rbonds, &modified_redelegation)?;
    } else {
        // Need to remove redelegation entries corresponding the outer epoch key
        for epoch_to_remove in &bonds_to_unbond.epochs {
            redelegated_bonds.remove_all(storage, epoch_to_remove)?;
        }
    }

    // `keysUnbonds`
    let unbond_keys = if let Some((start_epoch, _)) = bonds_to_unbond.new_entry
    {
        let mut to_remove = bonds_to_unbond.epochs.clone();
        to_remove.insert(start_epoch);
        to_remove
    } else {
        bonds_to_unbond.epochs.clone()
    };

    // `newUnbonds`
    // TODO: in-memory or directly into storage via Lazy?
    let new_unbonds_map = unbond_keys
        .into_iter()
        .map(|epoch| {
            let cur_bond_value = bonds_handle
                .get_delta_val(storage, epoch)
                .unwrap()
                .unwrap_or_default();
            let value = if let Some((start_epoch, new_bond_amount)) =
                bonds_to_unbond.new_entry
            {
                if start_epoch == epoch {
                    cur_bond_value - new_bond_amount
                } else {
                    cur_bond_value
                }
            } else {
                cur_bond_value
            };
            ((epoch, withdrawable_epoch), value)
        })
        .collect::<BTreeMap<(Epoch, Epoch), token::Change>>();

    // `updatedBonded`
    // Decrement the bonds in storage
    if let Some((bond_epoch, new_bond_amount)) = bonds_to_unbond.new_entry {
        for epoch in &bonds_to_unbond.epochs {
            bonds_handle.get_data_handler().remove(storage, epoch)?;
            bonds_handle.set(storage, new_bond_amount, bond_epoch, 0)?;
        }
    } else {
        for epoch in &bonds_to_unbond.epochs {
            bonds_handle.get_data_handler().remove(storage, epoch)?;
        }
    }

    // `updatedUnbonded`
    // TODO: can this be combined with the previous step?
    // TODO: figure out what I do here with both unbonds and unbond_records!
    // It seems that if this unbond is not a redelegation, then we update the
    // unbonds in storage with the `new_unbonds_map`. If it is a redelegation,
    // then we don't do anything with this new map in storage.
    // Yeah, we don't record unbonds for redelegations
    if !is_redelegation {
        for ((start_epoch, withdraw_epoch), unbond_amount) in
            new_unbonds_map.iter()
        {
            // TODO: check which epoch is first in unbonds_handle
            let cur_val = unbonds
                .at(start_epoch)
                .get(storage, withdraw_epoch)?
                .unwrap_or_default();
            unbonds.at(withdraw_epoch).insert(
                storage,
                *start_epoch,
                cur_val + token::Amount::from_change(*unbond_amount),
            )?;
        }
    }

    // NEW REDELEGATED UNBONDS
    // NOTE: I think we only need to update the redelegated unbonds if this is
    // NOT a redelegation
    // We should do this regardless - the `is_redelegation` is to determine if
    // the current call is from redelegation, but there might be redelegation
    // already that's being unbonded or re-redelegated which is being updated
    // here.
    // `newRedelegatedUnbonds`
    let new_redelegated_unbonds = compute_new_redelegated_unbonds(
        storage,
        &redelegated_bonds,
        &bonds_to_unbond.epochs,
        &modified_redelegation,
    )?;

    if !is_redelegation {
        // `val updatedRedelegatedUnbonded` with updates applied below
        let delegator_redelegated_unbonded =
            delegator_redelegated_unbonds_handle(source).at(validator);

        // Quint `def updateRedelegatedUnbonded` - not called when `if
        // is_redelegation`
        let new_epoch_pairs = new_redelegated_unbonds
            .keys()
            .map(|epoch| (*epoch, withdrawable_epoch))
            .collect::<HashSet<_>>();

        let existing_epoch_pairs = delegator_redelegated_unbonded
            .iter(storage)?
            .map(|res| {
                let (
                    NestedSubKey::Data {
                        key: start_epoch,
                        nested_sub_key:
                            NestedSubKey::Data {
                                key: withdraw_epoch,
                                nested_sub_key: _,
                            },
                    },
                    _,
                ) = res.unwrap();
                (start_epoch, withdraw_epoch)
            })
            .collect::<HashSet<_>>();

        let all_epoch_pairs = new_epoch_pairs
            .union(&existing_epoch_pairs)
            .cloned()
            .collect::<HashSet<_>>();
        // Quint `val updatedRedelegatedUnbonded` together with last statement
        // in `updatedDelegator.with("redelegatedUnbonded", ...`
        for pair in all_epoch_pairs.into_iter() {
            let in_existing = existing_epoch_pairs.contains(&pair);
            let in_new = new_epoch_pairs.contains(&pair);
            let (start, withdraw) = pair;

            let mut existing: EagerRedelegatedBondsMap = Default::default();
            let this_redelegated_unbonded =
                delegator_redelegated_unbonded.at(&start).at(&withdraw);
            for item in this_redelegated_unbonded.iter(storage)? {
                let (
                    NestedSubKey::Data {
                        key: validator,
                        nested_sub_key: SubKey::Data(epoch),
                    },
                    amount,
                ) = item?;
                existing
                    .entry(validator.clone())
                    .or_default()
                    .insert(epoch, amount);
            }

            if in_existing && in_new {
                let merged = merge_redelegated_bonds_map(
                    &existing,
                    new_redelegated_unbonds.get(&start).unwrap(),
                );
                for (validator, redelegated_unbonds) in merged {
                    for (redelegation_epoch, change) in redelegated_unbonds {
                        this_redelegated_unbonded.at(&validator).insert(
                            storage,
                            redelegation_epoch,
                            change,
                        )?;
                    }
                }
            } else if in_new {
                for (validator, redelegated_unbonds) in
                    new_redelegated_unbonds.get(&start).unwrap()
                {
                    for (redelegation_epoch, change) in redelegated_unbonds {
                        this_redelegated_unbonded.at(validator).insert(
                            storage,
                            *redelegation_epoch,
                            *change,
                        )?;
                    }
                }
            }
        }
    }
    // all `val updatedDelegator` changes are applied at this point

    // `val updatedTotalUnbonded` with `updatedValidator.with("totalUnbonded",
    // ..)` update
    let unbond_records = unbond_records_handle(validator).at(&pipeline_epoch);
    for ((start_epoch, _withdrawable_epoch), change) in &new_unbonds_map {
        let current = unbond_records
            .get(storage, start_epoch)?
            .unwrap_or_default();
        unbond_records.insert(
            storage,
            *start_epoch,
            current + token::Amount::from_change(*change),
        )?;
    }

    // `def updateTotalRedelegatedUnbonded` with
    // `updatedValidator.with("totalRedelegatedUnbonded", ..)`
    if !is_redelegation {
        // `newRedelegatedUnbonds` is not changed when `is_redelegation`

        let total_redelegated_unbonded =
            validator_total_redelegated_unbonded_handle(validator)
                .at(&pipeline_epoch);
        for (redelegation_start_epoch, unbonds) in &new_redelegated_unbonds {
            for (src_validator, changes) in unbonds {
                for (bond_start_epoch, change) in changes {
                    let sub_map = total_redelegated_unbonded
                        .at(redelegation_start_epoch)
                        .at(src_validator);
                    let current = sub_map
                        .get(storage, bond_start_epoch)?
                        .unwrap_or_default();
                    sub_map.insert(
                        storage,
                        *bond_start_epoch,
                        current + *change,
                    )?;
                }
            }
        }
    }

    // `val resultSlashing` and `def computeAmountAfterSlashingUnbond`
    let mut result_slashing = ResultSlashing::default();
    let slashes = find_validator_slashes(storage, validator)?;
    for ((start_epoch, withdrawable_epoch), change) in &new_unbonds_map {
        // `val listSlashes`
        let list_slashes: Vec<Slash> = slashes
            .iter()
            .filter(|slash| {
                &slash.epoch >= start_epoch && &slash.epoch < withdrawable_epoch
            })
            .cloned()
            .collect();
        // `val resultFold`
        let result_fold = if let Some(redelegated_unbonds) =
            new_redelegated_unbonds.get(start_epoch)
        {
            fold_and_slash_redelegated_bonds(
                storage,
                &params,
                redelegated_unbonds,
                start_epoch,
                &list_slashes,
                |_| true,
            )
        } else {
            FoldRedelegatedBondsResult::default()
        };
        // `val totalNoRedelegated`
        let total_not_redelegated =
            *change - result_fold.total_redelegated.change();
        // `val afterNoRedelegated`
        let after_not_redelegated =
            apply_list_slashes(&params, &list_slashes, total_not_redelegated);
        // `val amountAfterSlashing`
        let amount_after_slashing =
            after_not_redelegated + result_fold.total_after_slashing;
        // Accumulation step
        result_slashing.sum += amount_after_slashing;
        result_slashing
            .epoch_map
            .insert(*start_epoch, amount_after_slashing);
    }

    let amount_after_slashing = result_slashing.sum.change();
    // Update the validator set at the pipeline offset. Since unbonding from a
    // jailed validator who is no longer frozen is allowed, only update the
    // validator set if the validator is not jailed
    let is_jailed_at_pipeline = matches!(
        validator_state_handle(validator)
            .get(storage, pipeline_epoch, &params)?
            .unwrap(),
        ValidatorState::Jailed
    );
    if !is_jailed_at_pipeline {
        update_validator_set(
            storage,
            &params,
            validator,
            -amount_after_slashing,
            current_epoch,
        )?;
    }

    // Update the validator and total deltas at the pipeline offset
    update_validator_deltas(
        storage,
        validator,
        -amount_after_slashing,
        current_epoch,
        params.pipeline_len,
    )?;
    update_total_deltas(
        storage,
        -amount_after_slashing,
        current_epoch,
        params.pipeline_len,
    )?;

    // Should be all done at this point

    Ok(result_slashing)
}

#[derive(Debug, Default, Eq, PartialEq)]
struct FoldRedelegatedBondsResult {
    total_redelegated: token::Amount,
    total_after_slashing: token::Amount,
}

// `def foldRedelegatedBonds`
fn fold_and_slash_redelegated_bonds<S>(
    storage: &S,
    params: &PosParams,
    redelegated_unbonds: &EagerRedelegatedBondsMap,
    start_epoch: &Epoch,
    list_slashes: &[Slash],
    // _slashes: &[Slash],
    f: impl Fn(Epoch) -> bool,
) -> FoldRedelegatedBondsResult
where
    S: StorageRead,
{
    let (mut total_redelegated, mut total_after_slashing) =
        (token::Amount::zero(), token::Amount::zero());

    for (src_validator, bonds_map) in redelegated_unbonds {
        for (bond_start, amount) in bonds_map {
            let src_slashes = validator_slashes_handle(src_validator)
                .iter(storage)
                .unwrap()
                .map(Result::unwrap)
                .filter(|slash| {
                    params.in_redelegation_slashing_window(
                        slash.epoch,
                        params.redelegation_start_epoch_from_end(*start_epoch),
                        *start_epoch,
                    ) && *bond_start <= slash.epoch
                        && f(slash.epoch)
                })
                .collect::<Vec<_>>();

            // Merge the two lists of slashes
            // TODO: can I just combine these into a mutable list then sort?
            let mut merged = list_slashes
                .iter()
                .chain(src_slashes.iter())
                .cloned()
                .collect::<Vec<_>>();
            merged.sort_by(|s1, s2| s1.epoch.partial_cmp(&s2.epoch).unwrap());

            total_redelegated += token::Amount::from_change(*amount);
            total_after_slashing +=
                apply_list_slashes(params, &merged, *amount);
        }
    }

    FoldRedelegatedBondsResult {
        total_redelegated,
        total_after_slashing,
    }
}

// `def applyListSlashes`
fn apply_list_slashes(
    params: &PosParams,
    slashes: &Vec<Slash>,
    amount: token::Change,
) -> token::Amount {
    let mut final_amount = amount;
    let mut computed_slashes = BTreeMap::<Epoch, token::Change>::new();
    for slash in slashes {
        let slashed_amount =
            compute_slashable_amount(params, slash, amount, &computed_slashes);
        final_amount =
            cmp::max(token::Change::zero(), final_amount - slashed_amount);
        computed_slashes.insert(slash.epoch, slashed_amount);
    }
    token::Amount::from_change(final_amount)
}

// `def computeSlashableAmount`
fn compute_slashable_amount(
    params: &PosParams,
    slash: &Slash,
    amount: token::Change,
    computed_slashes: &BTreeMap<Epoch, token::Change>,
) -> token::Change {
    let updated_amount = computed_slashes
        .iter()
        .filter(|(&epoch, _)| {
            // TODO: check if bounds correct!
            // slashes that have already been applied and processed
            epoch + params.slash_processing_epoch_offset() <= slash.epoch
        })
        .fold(amount, |acc, (_, amnt)| {
            cmp::max(token::Change::zero(), acc - *amnt)
        });
    slash.rate * updated_amount
}

#[derive(Debug, Default)]
struct BondsForRemovalRes {
    pub epochs: HashSet<Epoch>,
    pub new_entry: Option<(Epoch, token::Change)>,
}

/// In decreasing epoch order, decrement the non-zero bond amount entries until
/// the full `amount` has been removed. Returns a `BondsForRemovalRes` object
/// that contains the epochs for which the full bond amount is removed and
/// additionally information for the one epoch whose bond amount is partially
/// removed, if any.
fn find_bonds_to_remove<S>(
    storage: &S,
    bonds_handle: &LazyMap<Epoch, token::Change>,
    amount: token::Change,
) -> storage_api::Result<BondsForRemovalRes>
where
    S: StorageRead,
{
    #[allow(clippy::needless_collect)]
    let bonds: Vec<Result<_, _>> = bonds_handle.iter(storage)?.collect();

    let mut bonds_for_removal = BondsForRemovalRes::default();
    let mut remaining = amount;

    for bond in bonds.into_iter().rev() {
        let (bond_epoch, bond_amount) = bond?;
        let to_unbond = cmp::min(bond_amount, remaining);
        if to_unbond == bond_amount {
            bonds_for_removal.epochs.insert(bond_epoch);
        } else {
            bonds_for_removal.new_entry =
                Some((bond_epoch, bond_amount - to_unbond));
        }
        remaining -= to_unbond;
        if remaining == token::Change::default() {
            break;
        }
    }
    Ok(bonds_for_removal)
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ModifiedRedelegation {
    epoch: Option<Epoch>,
    validators_to_remove: HashSet<Address>,
    validator_to_modify: Option<Address>,
    epochs_to_remove: HashSet<Epoch>,
    epoch_to_modify: Option<Epoch>,
    new_amount: Option<token::Change>,
}

fn compute_modified_redelegation<S>(
    storage: &S,
    redelegated_bonds: &RedelegatedBonds,
    start_epoch: Epoch,
    amount: token::Change,
) -> storage_api::Result<ModifiedRedelegation>
where
    S: StorageRead,
{
    let mut modified_redelegation = ModifiedRedelegation::default();

    let mut validators = HashSet::<Address>::new();
    let mut total_redelegated = token::Change::default();
    for rb in redelegated_bonds.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: validator,
                nested_sub_key: _,
            },
            amount,
        ) = rb?;
        total_redelegated += amount;
        validators.insert(validator);
    }

    if total_redelegated <= amount {
        return Ok(modified_redelegation);
    }

    modified_redelegation.epoch = Some(start_epoch);

    // TODO: desire some deterministic ordering of validators here (not
    // determined in Quint spec yet either)
    let mut remaining = amount;
    for src_validator in validators.into_iter() {
        if remaining == token::Change::default() {
            break;
        }
        let rbonds = redelegated_bonds.at(&src_validator);
        let total_src_val_amount = rbonds
            .iter(storage)?
            .map(|res| {
                let (_, amount) = res.unwrap();
                amount
            })
            .sum::<token::Change>();

        modified_redelegation
            .validators_to_remove
            .insert(src_validator.clone());
        if total_redelegated <= remaining {
            remaining -= total_src_val_amount;
        } else {
            remaining = token::Change::default();
            let bonds_to_remove =
                find_bonds_to_remove(storage, &rbonds, remaining)?;
            if let Some((bond_epoch, new_bond_amount)) =
                bonds_to_remove.new_entry
            {
                modified_redelegation.validator_to_modify = Some(src_validator);
                modified_redelegation.epochs_to_remove = {
                    let mut epochs = bonds_to_remove.epochs;
                    epochs.insert(bond_epoch);
                    epochs
                };
                modified_redelegation.epoch_to_modify = Some(bond_epoch);
                modified_redelegation.new_amount = Some(new_bond_amount);
            } else {
                modified_redelegation.validator_to_modify = Some(src_validator);
                modified_redelegation.epochs_to_remove = bonds_to_remove.epochs;
            }
        }
    }
    Ok(modified_redelegation)
}

fn update_redelegated_bonds<S>(
    storage: &mut S,
    redelegated_bonds: &RedelegatedBonds,
    modified_redelegation: &ModifiedRedelegation,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    if let Some(val_to_modify) = &modified_redelegation.validator_to_modify {
        let mut updated_vals_to_remove =
            modified_redelegation.validators_to_remove.clone();
        updated_vals_to_remove.remove(val_to_modify);

        if let Some(epoch_to_modify) = modified_redelegation.epoch_to_modify {
            let mut updated_epochs_to_remove =
                modified_redelegation.epochs_to_remove.clone();
            updated_epochs_to_remove.remove(&epoch_to_modify);
            let val_bonds_to_modify = redelegated_bonds.at(val_to_modify);
            for epoch in updated_epochs_to_remove {
                val_bonds_to_modify.remove(storage, &epoch)?;
            }
            val_bonds_to_modify.insert(
                storage,
                epoch_to_modify,
                modified_redelegation.new_amount.unwrap(),
            )?;
            // Then, remove the updated_vals_to_remove keys from the
            // redelegated_bonds map before doing...
        } else {
            // Remove the updated_vals_to_remove keys from the redelegated_bonds
            // map first
            for val in &updated_vals_to_remove {
                redelegated_bonds.remove_all(storage, val)?;
            }
            // Then remove to epochs_to_remove from the redelegated bonds of the
            // val_to_modify
            let val_bonds_to_modify = redelegated_bonds.at(val_to_modify);
            for epoch in &modified_redelegation.epochs_to_remove {
                val_bonds_to_modify.remove(storage, epoch)?;
            }
        }
    } else {
        // Remove all validators in modified_redelegation.validators_to_remove
        // from redelegated_bonds
        for val in &modified_redelegation.validators_to_remove {
            redelegated_bonds.remove_all(storage, val)?;
        }
    }
    Ok(())
}

/// Temp helper type to match quint model
/// TODO: refactor out
type EagerRedelegatedUnbonds = BTreeMap<
    // redelegation end epoch
    Epoch,
    EagerRedelegatedBondsMap,
>;

/// `computeNewRedelegatedUnbonds` from Quint
/// Check assumptions in the Quint spec namada-redelegation.qnt
/// TODO: try to optimize this by only writing to storage via Lazy!
fn compute_new_redelegated_unbonds<S>(
    storage: &mut S,
    redelegated_bonds: &NestedMap<Epoch, RedelegatedBonds>,
    epochs_to_remove: &HashSet<Epoch>,
    modified_redelegation: &ModifiedRedelegation,
) -> storage_api::Result<EagerRedelegatedUnbonds>
where
    S: StorageRead + StorageWrite,
{
    let unbonded_epochs = if let Some(epoch) = modified_redelegation.epoch {
        let mut epochs = epochs_to_remove.clone();
        epochs.insert(epoch);
        epochs
            .iter()
            .cloned()
            .filter(|e| redelegated_bonds.contains(storage, e).unwrap())
            .collect::<HashSet<Epoch>>()
    } else {
        epochs_to_remove
            .iter()
            .cloned()
            .filter(|e| redelegated_bonds.contains(storage, e).unwrap())
            .collect::<HashSet<Epoch>>()
    };

    // quint `newRedelegatedUnbonds` returned from
    // `computeNewRedelegatedUnbonds`
    let new_redelegated_unbonds: EagerRedelegatedUnbonds = unbonded_epochs
        .into_iter()
        .map(|start| {
            let mut rbonds = EagerRedelegatedBondsMap::default();
            if modified_redelegation
                .epoch
                .map(|redelegation_epoch| start != redelegation_epoch)
                .unwrap_or(true)
            {
                for res in redelegated_bonds.at(&start).iter(storage).unwrap() {
                    let (
                        NestedSubKey::Data {
                            key: validator,
                            nested_sub_key: SubKey::Data(epoch),
                        },
                        amount,
                    ) = res.unwrap();
                    rbonds
                        .entry(validator.clone())
                        .or_default()
                        .insert(epoch, amount);
                }
                (start, rbonds)
            } else {
                for src_validator in &modified_redelegation.validators_to_remove
                {
                    if modified_redelegation
                        .validator_to_modify
                        .as_ref()
                        .map(|validator| src_validator != validator)
                        .unwrap_or(true)
                    {
                        let raw_bonds =
                            redelegated_bonds.at(&start).at(src_validator);
                        for res in raw_bonds.iter(storage).unwrap() {
                            let (bond_epoch, bond_amount) = res.unwrap();
                            rbonds
                                .entry(src_validator.clone())
                                .or_default()
                                .insert(bond_epoch, bond_amount);
                        }
                    } else {
                        for bond_start in
                            &modified_redelegation.epochs_to_remove
                        {
                            let cur_redel_bond_amount = redelegated_bonds
                                .at(&start)
                                .at(src_validator)
                                .get(storage, bond_start)
                                .unwrap()
                                .unwrap_or_default();
                            let raw_bonds = rbonds
                                .entry(src_validator.clone())
                                .or_default();
                            if modified_redelegation
                                .epoch_to_modify
                                .as_ref()
                                .map(|epoch| bond_start != epoch)
                                .unwrap_or(true)
                            {
                                raw_bonds
                                    .insert(*bond_start, cur_redel_bond_amount);
                            } else {
                                raw_bonds.insert(
                                    *bond_start,
                                    cur_redel_bond_amount
                                        - modified_redelegation
                                            .new_amount
                                            // Safe unwrap - it shouldn't
                                            // get to
                                            // this if it's None
                                            .unwrap(),
                                );
                            }
                        }
                    }
                }
                (start, rbonds)
            }
        })
        .collect();

    Ok(new_redelegated_unbonds)
}

fn merge_redelegated_bonds_map(
    map1: &EagerRedelegatedBondsMap,
    map2: &EagerRedelegatedBondsMap,
) -> EagerRedelegatedBondsMap {
    let all_keys = map1
        .keys()
        .chain(map2.keys())
        .cloned()
        .collect::<HashSet<_>>();
    all_keys
        .into_iter()
        .map(|address| {
            let bonds1 = map1.get(&address).cloned();
            let bonds2 = map2.get(&address).cloned();
            if let (Some(bonds1), Some(bonds2)) =
                (bonds1.clone(), bonds2.clone())
            {
                let total_bonds = bonds1
                    .keys()
                    .chain(bonds2.keys())
                    .cloned()
                    .map(|epoch| {
                        let val1 =
                            bonds1.get(&epoch).cloned().unwrap_or_default();
                        let val2 =
                            bonds2.get(&epoch).cloned().unwrap_or_default();
                        (epoch, val1 + val2)
                    })
                    .collect::<BTreeMap<_, _>>();
                (address, total_bonds)
            } else if let Some(bonds1) = bonds1 {
                (address, bonds1)
            } else if let Some(bonds2) = bonds2 {
                (address, bonds2)
            } else {
                panic!(
                    "Should never be passing two empty maps into \
                     `merge_redelegated_bonds_map`"
                );
            }
        })
        .collect()
}

/// Compute a token amount after slashing, given the initial amount and a set of
/// slashes. It is assumed that the input `slashes` are those commited while the
/// `amount` was contributing to voting power.
fn get_slashed_amount(
    params: &PosParams,
    amount: token::Amount,
    slashes: &BTreeMap<Epoch, Dec>,
) -> storage_api::Result<token::Change> {
    // println!("FN `get_slashed_amount`");

    let mut updated_amount = amount;
    let mut computed_amounts = Vec::<SlashedAmount>::new();

    for (infraction_epoch, slash_rate) in slashes {
        // println!("Slash epoch: {}, rate: {}", infraction_epoch, slash_rate);
        let mut computed_to_remove = BTreeSet::<Reverse<usize>>::new();
        for (ix, slashed_amount) in computed_amounts.iter().enumerate() {
            // Update amount with slashes that happened more than unbonding_len
            // epochs before this current slash
            // TODO: understand this better (from Informal)
            // TODO: do bounds of this need to be changed with a +/- 1??
            if slashed_amount.epoch + params.slash_processing_epoch_offset()
                <= *infraction_epoch
            {
                updated_amount = updated_amount
                    .checked_sub(slashed_amount.amount)
                    .unwrap_or_default();
                computed_to_remove.insert(Reverse(ix));
            }
        }
        // Invariant: `computed_to_remove` must be in reverse ord to avoid
        // left-shift of the `computed_amounts` after call to `remove`
        // invalidating the rest of the indices.
        for item in computed_to_remove {
            computed_amounts.remove(item.0);
        }
        computed_amounts.push(SlashedAmount {
            amount: *slash_rate * updated_amount,
            epoch: *infraction_epoch,
        });
    }
    // println!("Finished loop over slashes in `get_slashed_amount`");
    // println!("Updated amount: {:?}", &updated_amount);
    // println!("Computed amounts: {:?}", &computed_amounts);

    let total_computed_amounts = computed_amounts
        .into_iter()
        .map(|slashed| slashed.amount)
        .sum();

    let final_amount = updated_amount
        .checked_sub(total_computed_amounts)
        .unwrap_or_default();

    Ok(final_amount.change())
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

/// Arguments to [`become_validator`].
pub struct BecomeValidator<'a, S> {
    /// Storage implementation.
    pub storage: &'a mut S,
    /// Proof-of-stake parameters.
    pub params: &'a PosParams,
    /// The validator's address.
    pub address: &'a Address,
    /// The validator's consensus key, used by Tendermint.
    pub consensus_key: &'a common::PublicKey,
    /// The validator's Ethereum bridge cold key.
    pub eth_cold_key: &'a common::PublicKey,
    /// The validator's Ethereum bridge hot key.
    pub eth_hot_key: &'a common::PublicKey,
    /// The numeric value of the current epoch.
    pub current_epoch: Epoch,
    /// Commission rate.
    pub commission_rate: Dec,
    /// Max commission rate change.
    pub max_commission_rate_change: Dec,
}

/// Initialize data for a new validator.
pub fn become_validator<S>(
    args: BecomeValidator<'_, S>,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let BecomeValidator {
        storage,
        params,
        address,
        consensus_key,
        eth_cold_key,
        eth_hot_key,
        current_epoch,
        commission_rate,
        max_commission_rate_change,
    } = args;

    // This will fail if the key is already being used
    try_insert_consensus_key(storage, consensus_key)?;

    let pipeline_epoch = current_epoch + params.pipeline_len;
    validator_addresses_handle()
        .at(&pipeline_epoch)
        .insert(storage, address.clone())?;

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
    validator_eth_hot_key_handle(address).set(
        storage,
        eth_hot_key.clone(),
        current_epoch,
        params.pipeline_len,
    )?;
    validator_eth_cold_key_handle(address).set(
        storage,
        eth_cold_key.clone(),
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

    // The validator's stake at initialization is 0, so its state is immediately
    // below-threshold
    validator_state_handle(address).set(
        storage,
        ValidatorState::BelowThreshold,
        current_epoch,
        params.pipeline_len,
    )?;

    Ok(())
}

/// Withdraw tokens from those that have been unbonded from proof-of-stake
pub fn withdraw_tokens<S>(
    storage: &mut S,
    source: Option<&Address>,
    validator: &Address,
    current_epoch: Epoch,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead + StorageWrite,
{
    let params = read_pos_params(storage)?;
    let source = source.unwrap_or(validator);

    tracing::debug!("Withdrawing tokens in epoch {current_epoch}");
    tracing::debug!("Source {} --> Validator {}", source, validator);

    let unbond_handle = unbond_handle(source, validator);
    let redelegated_unbonds =
        delegator_redelegated_unbonds_handle(source).at(validator);

    // Check that there are unbonded tokens available for withdrawal
    if unbond_handle.is_empty(storage)? {
        return Err(WithdrawError::NoUnbondFound(BondId {
            source: source.clone(),
            validator: validator.clone(),
        })
        .into());
    }

    let mut result_slashing = ResultSlashing::default();
    let mut unbonds_to_remove: Vec<(Epoch, Epoch)> = Vec::new();

    for unbond in unbond_handle.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: withdraw_epoch,
                nested_sub_key: SubKey::Data(start_epoch),
            },
            amount,
        ) = unbond?;

        // Logging
        tracing::debug!(
            "Unbond delta ({start_epoch}..{withdraw_epoch}), amount {}",
            amount.to_string_native()
        );
        if withdraw_epoch > current_epoch {
            tracing::debug!(
                "Not yet withdrawable until epoch {withdraw_epoch}"
            );
            continue;
        }

        // TODO: check the bounds, and check if slashes in the same epoch can be
        // folded into one effective slash
        let list_slashes = validator_slashes_handle(validator)
            .iter(storage)?
            .map(Result::unwrap)
            .filter(|slash| {
                start_epoch <= slash.epoch
                    // TODO: check bounds here!
                    && withdraw_epoch - params.slash_processing_epoch_offset()
                        > slash.epoch
            })
            .collect::<Vec<_>>();

        let matching_redelegated_unbonds =
            redelegated_unbonds.at(&start_epoch).at(&withdraw_epoch);
        let mut eager_redelegated_unbonds = EagerRedelegatedBondsMap::default();
        for ub in matching_redelegated_unbonds.iter(storage)? {
            let (
                NestedSubKey::Data {
                    key: address,
                    nested_sub_key: SubKey::Data(epoch),
                },
                amount,
            ) = ub?;
            eager_redelegated_unbonds
                .entry(address)
                .or_default()
                .entry(epoch)
                .or_insert(amount);
        }

        let result_fold = if !matching_redelegated_unbonds.is_empty(storage)? {
            fold_and_slash_redelegated_bonds(
                storage,
                &params,
                &eager_redelegated_unbonds,
                &start_epoch,
                &list_slashes,
                |_| true,
            )
        } else {
            FoldRedelegatedBondsResult::default()
        };

        let total_not_redelegated = amount - result_fold.total_redelegated;
        let after_not_redelegated = apply_list_slashes(
            &params,
            &list_slashes,
            total_not_redelegated.change(),
        );

        let amount_after_slashing =
            after_not_redelegated + result_fold.total_after_slashing;

        result_slashing.sum += amount_after_slashing;
        result_slashing
            .epoch_map
            .insert(start_epoch, amount_after_slashing);

        unbonds_to_remove.push((withdraw_epoch, start_epoch));
    }
    let withdrawable_amount = result_slashing.sum;
    tracing::debug!(
        "Withdrawing total {}",
        withdrawable_amount.to_string_native()
    );

    // `updateDelegator` with `unbonded` and `redelegeatedUnbonded`
    for (withdraw_epoch, start_epoch) in unbonds_to_remove {
        tracing::debug!("Remove ({start_epoch}..{withdraw_epoch}) from unbond");
        unbond_handle
            .at(&withdraw_epoch)
            .remove(storage, &start_epoch)?;
        redelegated_unbonds
            .at(&start_epoch)
            .remove_all(storage, &withdraw_epoch)?;

        // TODO: check if the outer keys are now empty
        if unbond_handle.at(&withdraw_epoch).is_empty(storage)? {
            unbond_handle.remove_all(storage, &withdraw_epoch)?;
        }
        if redelegated_unbonds.at(&start_epoch).is_empty(storage)? {
            redelegated_unbonds.remove_all(storage, &start_epoch)?;
        }
    }

    // Transfer the withdrawable tokens from the PoS address back to the source
    let staking_token = staking_token_address(storage);
    transfer_tokens(
        storage,
        &staking_token,
        withdrawable_amount,
        &ADDRESS,
        source,
    )?;

    // TODO: Transfer the slashed tokens from the PoS address to the Slash Pool
    // address
    // transfer_tokens(
    //     storage,
    //     &staking_token,
    //     total_slashed,
    //     &ADDRESS,
    //     &SLASH_POOL_ADDRESS,
    // )?;

    Ok(withdrawable_amount)
}

/// Withdraw tokens from those that have been unbonded from proof-of-stake
pub fn withdraw_tokens_old<S>(
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
    tracing::debug!("Source {} --> Validator {}", source, validator);

    let unbond_handle = unbond_handle(source, validator);
    if unbond_handle.is_empty(storage)? {
        return Err(WithdrawError::NoUnbondFound(BondId {
            source: source.clone(),
            validator: validator.clone(),
        })
        .into());
    }

    // let mut total_slashed = token::Amount::default();
    let mut withdrawable_amount = token::Amount::default();
    // (withdraw_epoch, start_epoch)
    let mut unbonds_to_remove: Vec<(Epoch, Epoch)> = Vec::new();

    for unbond in unbond_handle.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: withdraw_epoch,
                nested_sub_key: SubKey::Data(start_epoch),
            },
            amount,
        ) = unbond?;

        tracing::debug!(
            "Unbond delta ({start_epoch}..{withdraw_epoch}), amount {}",
            amount.to_string_native()
        );

        // TODO: adding slash rates in same epoch, applying cumulatively in dif
        // epochs
        if withdraw_epoch > current_epoch {
            tracing::debug!(
                "Not yet withdrawable until epoch {withdraw_epoch}"
            );
            continue;
        }
        let slashes_for_this_unbond = find_slashes_in_range(
            storage,
            start_epoch,
            Some(
                withdraw_epoch
                    - params.unbonding_len
                    - params.cubic_slashing_window_length,
            ),
            validator,
        )?;

        let amount_after_slashing =
            get_slashed_amount(&params, amount, &slashes_for_this_unbond)?;

        // total_slashed += amount - token::Amount::from(amount_after_slashing);
        withdrawable_amount += token::Amount::from(amount_after_slashing);
        unbonds_to_remove.push((withdraw_epoch, start_epoch));
    }
    tracing::debug!(
        "Withdrawing total {}",
        withdrawable_amount.to_string_native()
    );

    // Remove the unbond data from storage
    for (withdraw_epoch, start_epoch) in unbonds_to_remove {
        tracing::debug!("Remove ({start_epoch}..{withdraw_epoch}) from unbond");
        unbond_handle
            .at(&withdraw_epoch)
            .remove(storage, &start_epoch)?;
        // TODO: check if the `end_epoch` layer is now empty and remove it if
        // so, may need to implement remove/delete for nested map
    }

    // Transfer the withdrawable tokens from the PoS address back to the source
    let staking_token = staking_token_address(storage);
    transfer_tokens(
        storage,
        &staking_token,
        withdrawable_amount,
        &ADDRESS,
        source,
    )?;

    // TODO: Transfer the slashed tokens from the PoS address to the Slash Pool
    // address
    // transfer_tokens(
    //     storage,
    //     &staking_token,
    //     total_slashed,
    //     &ADDRESS,
    //     &SLASH_POOL_ADDRESS,
    // )?;

    Ok(withdrawable_amount)
}

/// Change the commission rate of a validator
pub fn change_validator_commission_rate<S>(
    storage: &mut S,
    validator: &Address,
    new_rate: Dec,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    // if new_rate < Uint::zero() {
    //     return Err(CommissionRateChangeError::NegativeRate(
    //         new_rate,
    //         validator.clone(),
    //     )
    //     .into());
    // }

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
        .get(storage, pipeline_epoch.prev(), &params)?
        .expect("Could not find a rate in given epoch");

    // TODO: change this back if we use `Dec` type with a signed integer
    // let change_from_prev = new_rate - rate_before_pipeline;
    // if change_from_prev.abs() > max_change.unwrap() {
    let change_from_prev = if new_rate > rate_before_pipeline {
        new_rate - rate_before_pipeline
    } else {
        rate_before_pipeline - new_rate
    };
    if change_from_prev > max_change.unwrap() {
        return Err(CommissionRateChangeError::RateChangeTooLarge(
            change_from_prev,
            validator.clone(),
        )
        .into());
    }

    commission_handle.set(storage, new_rate, current_epoch, params.pipeline_len)
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
                src_balance.to_string_native(),
                amount.to_string_native(),
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

/// Get the total bond amount, including slashes, for a given bond ID and epoch.
/// Returns a two-element tuple of the raw bond amount and the post-slashed bond
/// amount, respectively.
///
/// TODO: does epoch of discovery need to be considered for precise accuracy?
pub fn bond_amount<S>(
    storage: &S,
    bond_id: &BondId,
    epoch: Epoch,
) -> storage_api::Result<(token::Amount, token::Amount)>
where
    S: StorageRead,
{
    // TODO: review this logic carefully, apply rewards
    let slashes = find_validator_slashes(storage, &bond_id.validator)?;
    let slash_rates = slashes.into_iter().fold(
        BTreeMap::<Epoch, Dec>::new(),
        |mut map, slash| {
            let tot_rate = map.entry(slash.epoch).or_default();
            *tot_rate = cmp::min(Dec::one(), *tot_rate + slash.rate);
            map
        },
    );

    let bonds =
        bond_handle(&bond_id.source, &bond_id.validator).get_data_handler();
    let mut total = token::Amount::default();
    let mut total_active = token::Amount::default();
    for next in bonds.iter(storage)? {
        let (bond_epoch, delta) = next?;
        if bond_epoch > epoch {
            continue;
        }

        total += token::Amount::from(delta);
        total_active += token::Amount::from(delta);

        for (slash_epoch, rate) in &slash_rates {
            if *slash_epoch < bond_epoch {
                continue;
            }
            // TODO: think about truncation
            let current_slashed = *rate * delta;
            total_active
                .checked_sub(token::Amount::from(current_slashed))
                .unwrap_or_default();
        }
    }
    Ok((total, total_active))
}

/// Get the genesis consensus validators stake and consensus key for Tendermint,
/// converted from [`ValidatorSetUpdate`]s using the given function.
pub fn genesis_validator_set_tendermint<S, T>(
    storage: &S,
    params: &PosParams,
    current_epoch: Epoch,
    mut f: impl FnMut(ValidatorSetUpdate) -> T,
) -> storage_api::Result<Vec<T>>
where
    S: StorageRead,
{
    let consensus_validator_handle =
        consensus_validator_set_handle().at(&current_epoch);
    let iter = consensus_validator_handle.iter(storage)?;

    iter.map(|validator| {
        let (
            NestedSubKey::Data {
                key: new_stake,
                nested_sub_key: _,
            },
            address,
        ) = validator?;
        let consensus_key = validator_consensus_key_handle(&address)
            .get(storage, current_epoch, params)?
            .unwrap();
        let converted = f(ValidatorSetUpdate::Consensus(ConsensusValidator {
            consensus_key,
            bonded_stake: new_stake,
        }));
        Ok(converted)
    })
    .collect()
}

/// Communicate imminent validator set updates to Tendermint. This function is
/// called two blocks before the start of a new epoch because Tendermint
/// validator updates become active two blocks after the updates are submitted.
pub fn validator_set_update_tendermint<S, T>(
    storage: &S,
    params: &PosParams,
    current_epoch: Epoch,
    f: impl FnMut(ValidatorSetUpdate) -> T,
) -> storage_api::Result<Vec<T>>
where
    S: StorageRead,
{
    tracing::debug!("Communicating validator set updates to Tendermint.");
    // Because this is called 2 blocks before a start on an epoch, we're gonna
    // give Tendermint updates for the next epoch
    let next_epoch: Epoch = current_epoch.next();

    let new_consensus_validator_handle =
        consensus_validator_set_handle().at(&next_epoch);
    let prev_consensus_validator_handle =
        consensus_validator_set_handle().at(&current_epoch);

    let new_consensus_validators = new_consensus_validator_handle
        .iter(storage)?
        .filter_map(|validator| {
            let (
                NestedSubKey::Data {
                    key: new_stake,
                    nested_sub_key: _,
                },
                address,
            ) = validator.unwrap();

            tracing::debug!(
                "Consensus validator address {address}, stake {}",
                new_stake.to_string_native()
            );

            // Check if the validator was consensus in the previous epoch with
            // the same stake. If so, no updated is needed.
            // Look up previous state and prev and current voting powers
            if !prev_consensus_validator_handle.is_empty(storage).unwrap() {
                let prev_state = validator_state_handle(&address)
                    .get(storage, current_epoch, params)
                    .unwrap();
                let prev_tm_voting_power = Lazy::new(|| {
                    let prev_validator_stake = read_validator_stake(
                        storage,
                        params,
                        &address,
                        current_epoch,
                    )
                    .unwrap()
                    .unwrap_or_default();
                    into_tm_voting_power(
                        params.tm_votes_per_token,
                        prev_validator_stake,
                    )
                });
                let new_tm_voting_power = Lazy::new(|| {
                    into_tm_voting_power(params.tm_votes_per_token, new_stake)
                });

                // If it was in `Consensus` before and voting power has not
                // changed, skip the update
                if matches!(prev_state, Some(ValidatorState::Consensus))
                    && *prev_tm_voting_power == *new_tm_voting_power
                {
                    tracing::debug!(
                        "skipping validator update, {address} is in consensus \
                         set but voting power hasn't changed"
                    );
                    return None;
                }
                // If both previous and current voting powers are 0, and the
                // validator_stake_threshold is 0, skip update
                if params.validator_stake_threshold == token::Amount::default()
                    && *prev_tm_voting_power == 0
                    && *new_tm_voting_power == 0
                {
                    tracing::info!(
                        "skipping validator update, {address} is in consensus \
                         set but without voting power"
                    );
                    return None;
                }
                // TODO: maybe debug_assert that the new stake is >= threshold?
            }
            let consensus_key = validator_consensus_key_handle(&address)
                .get(storage, next_epoch, params)
                .unwrap()
                .unwrap();
            tracing::debug!(
                "{address} consensus key {}",
                consensus_key.tm_raw_hash()
            );
            Some(ValidatorSetUpdate::Consensus(ConsensusValidator {
                consensus_key,
                bonded_stake: new_stake,
            }))
        });

    let prev_consensus_validators = prev_consensus_validator_handle
        .iter(storage)?
        .filter_map(|validator| {
            let (
                NestedSubKey::Data {
                    key: _prev_stake,
                    nested_sub_key: _,
                },
                address,
            ) = validator.unwrap();

            let new_state = validator_state_handle(&address)
                .get(storage, next_epoch, params)
                .unwrap();

            let prev_tm_voting_power = Lazy::new(|| {
                let prev_validator_stake = read_validator_stake(
                    storage,
                    params,
                    &address,
                    current_epoch,
                )
                .unwrap()
                .unwrap_or_default();
                into_tm_voting_power(
                    params.tm_votes_per_token,
                    prev_validator_stake,
                )
            });

            // If the validator is still in the Consensus set, we accounted for
            // it in the `new_consensus_validators` iterator above
            if matches!(new_state, Some(ValidatorState::Consensus)) {
                return None;
            } else if params.validator_stake_threshold
                == token::Amount::default()
                && *prev_tm_voting_power == 0
            {
                // If the new state is not Consensus but its prev voting power
                // was 0 and the stake threshold is 0, we can also skip the
                // update
                tracing::info!(
                    "skipping validator update, {address} is in consensus set \
                     but without voting power"
                );
                return None;
            }

            // The remaining validators were previously Consensus but no longer
            // are, so they must be deactivated
            let consensus_key = validator_consensus_key_handle(&address)
                .get(storage, next_epoch, params)
                .unwrap()
                .unwrap();
            tracing::debug!(
                "{address} consensus key {}",
                consensus_key.tm_raw_hash()
            );
            Some(ValidatorSetUpdate::Deactivated(consensus_key))
        });

    Ok(new_consensus_validators
        .chain(prev_consensus_validators)
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

/// Find raw bond deltas for the given source and validator address.
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

/// Find raw unbond deltas for the given source and validator address.
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

/// Collect the details of all of the enqueued slashes to be processed in future
/// epochs into a nested map
pub fn find_all_enqueued_slashes<S>(
    storage: &S,
    epoch: Epoch,
) -> storage_api::Result<HashMap<Address, BTreeMap<Epoch, Vec<Slash>>>>
where
    S: StorageRead,
{
    let mut enqueued = HashMap::<Address, BTreeMap<Epoch, Vec<Slash>>>::new();
    for res in enqueued_slashes_handle().get_data_handler().iter(storage)? {
        let (
            NestedSubKey::Data {
                key: processing_epoch,
                nested_sub_key:
                    NestedSubKey::Data {
                        key: address,
                        nested_sub_key: _,
                    },
            },
            slash,
        ) = res?;
        if processing_epoch <= epoch {
            continue;
        }

        let slashes = enqueued
            .entry(address)
            .or_default()
            .entry(processing_epoch)
            .or_default();
        slashes.push(slash);
    }
    Ok(enqueued)
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
    let mut applied_slashes = HashMap::<Address, Vec<Slash>>::new();

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
                    if change.is_zero() {
                        return None;
                    }
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
                if let Some((bond_id, start, withdraw)) = is_unbond_key(&key) {
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
                    match (source.clone(), validator.clone()) {
                        (None, Some(validator)) => {
                            if bond_id.validator != validator {
                                return None;
                            }
                        }
                        (Some(owner), None) => {
                            if owner != bond_id.source {
                                return None;
                            }
                        }
                        _ => {}
                    }
                    let amount: token::Amount =
                        BorshDeserialize::try_from_slice(&val_bytes).ok()?;
                    return Some((bond_id, start, withdraw, amount));
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
    let mut applied_slashes = HashMap::<Address, Vec<Slash>>::new();

    let bonds = find_bonds(storage, &source, &validator)?
        .into_iter()
        .filter(|(_start, change)| *change > token::Change::default())
        .map(|(start, change)| {
            make_bond_details(
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

fn make_bond_details(
    params: &PosParams,
    validator: &Address,
    change: token::Change,
    start: Epoch,
    slashes: &[Slash],
    applied_slashes: &mut HashMap<Address, Vec<Slash>>,
) -> BondDetails {
    let prev_applied_slashes = applied_slashes
        .clone()
        .get(validator)
        .cloned()
        .unwrap_or_default();
    let amount = token::Amount::from_change(change);
    let mut slash_rates_by_epoch = BTreeMap::<Epoch, Dec>::new();

    let validator_slashes =
        applied_slashes.entry(validator.clone()).or_default();
    for slash in slashes {
        if slash.epoch >= start {
            let cur_rate = slash_rates_by_epoch.entry(slash.epoch).or_default();
            *cur_rate = cmp::min(Dec::one(), *cur_rate + slash.rate);

            if !prev_applied_slashes.iter().any(|s| s == slash) {
                validator_slashes.push(slash.clone());
            }
        }
    }

    let slashed_amount = if slash_rates_by_epoch.is_empty() {
        None
    } else {
        let amount_after_slashing = token::Amount::from_change(
            get_slashed_amount(params, amount, &slash_rates_by_epoch).unwrap(),
        );
        Some(amount - amount_after_slashing)
    };

    BondDetails {
        start,
        amount,
        slashed_amount,
    }
}

fn make_unbond_details(
    params: &PosParams,
    validator: &Address,
    amount: token::Amount,
    (start, withdraw): (Epoch, Epoch),
    slashes: &[Slash],
    applied_slashes: &mut HashMap<Address, Vec<Slash>>,
) -> UnbondDetails {
    let prev_applied_slashes = applied_slashes
        .clone()
        .get(validator)
        .cloned()
        .unwrap_or_default();
    let mut slash_rates_by_epoch = BTreeMap::<Epoch, Dec>::new();

    let validator_slashes =
        applied_slashes.entry(validator.clone()).or_default();
    for slash in slashes {
        if slash.epoch >= start
            && slash.epoch
                < withdraw
                    .checked_sub(Epoch(
                        params.unbonding_len
                            + params.cubic_slashing_window_length,
                    ))
                    .unwrap_or_default()
        {
            let cur_rate = slash_rates_by_epoch.entry(slash.epoch).or_default();
            *cur_rate = cmp::min(Dec::one(), *cur_rate + slash.rate);

            if !prev_applied_slashes.iter().any(|s| s == slash) {
                validator_slashes.push(slash.clone());
            }
        }
    }

    let slashed_amount = if slash_rates_by_epoch.is_empty() {
        None
    } else {
        let amount_after_slashing = token::Amount::from_change(
            get_slashed_amount(params, amount, &slash_rates_by_epoch).unwrap(),
        );
        Some(amount - amount_after_slashing)
    };

    UnbondDetails {
        start,
        withdraw,
        amount,
        slashed_amount,
    }
}

/// Tally a running sum of the fraction of rewards owed to each validator in
/// the consensus set. This is used to keep track of the rewards due to each
/// consensus validator over the lifetime of an epoch.
pub fn log_block_rewards<S>(
    storage: &mut S,
    epoch: impl Into<Epoch>,
    proposer_address: &Address,
    votes: Vec<VoteInfo>,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    // The votes correspond to the last committed block (n-1 if we are
    // finalizing block n)

    let epoch: Epoch = epoch.into();
    let params = read_pos_params(storage)?;
    let consensus_validators = consensus_validator_set_handle().at(&epoch);

    // Get total stake of the consensus validator set
    let mut total_consensus_stake = token::Amount::default();
    for validator in consensus_validators.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: amount,
                nested_sub_key: _,
            },
            _address,
        ) = validator?;
        total_consensus_stake += amount;
    }

    // Get set of signing validator addresses and the combined stake of
    // these signers
    let mut signer_set: HashSet<Address> = HashSet::new();
    let mut total_signing_stake = token::Amount::default();
    for VoteInfo {
        validator_address,
        validator_vp,
    } in votes
    {
        if validator_vp == 0 {
            continue;
        }
        // Ensure that the validator is not currently jailed or other
        let state = validator_state_handle(&validator_address)
            .get(storage, epoch, &params)?;
        if state != Some(ValidatorState::Consensus) {
            return Err(InflationError::ExpectedValidatorInConsensus(
                validator_address,
                state,
            ))
            .into_storage_result();
        }

        let stake_from_deltas =
            read_validator_stake(storage, &params, &validator_address, epoch)?
                .unwrap_or_default();

        // Ensure TM stake updates properly with a debug_assert
        if cfg!(debug_assertions) {
            debug_assert_eq!(
                into_tm_voting_power(
                    params.tm_votes_per_token,
                    stake_from_deltas,
                ),
                i64::try_from(validator_vp).unwrap_or_default(),
            );
        }

        signer_set.insert(validator_address);
        total_signing_stake += stake_from_deltas;
    }

    // Get the block rewards coefficients (proposing, signing/voting,
    // consensus set status)
    let rewards_calculator = PosRewardsCalculator {
        proposer_reward: params.block_proposer_reward,
        signer_reward: params.block_vote_reward,
        signing_stake: total_signing_stake,
        total_stake: total_consensus_stake,
    };
    let coeffs = rewards_calculator
        .get_reward_coeffs()
        .map_err(InflationError::Rewards)
        .into_storage_result()?;
    tracing::debug!(
        "PoS rewards coefficients {coeffs:?}, inputs: {rewards_calculator:?}."
    );

    // println!(
    //     "TOTAL SIGNING STAKE (LOGGING BLOCK REWARDS) = {}",
    //     signing_stake
    // );

    // Compute the fractional block rewards for each consensus validator and
    // update the reward accumulators
    let consensus_stake_unscaled: Dec = total_consensus_stake.into();
    let signing_stake_unscaled: Dec = total_signing_stake.into();
    let mut values: HashMap<Address, Dec> = HashMap::new();
    for validator in consensus_validators.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: stake,
                nested_sub_key: _,
            },
            address,
        ) = validator?;

        // TODO:
        // When below-threshold validator set is added, this shouldn't be needed
        // anymore since some minimal stake will be required to be in at least
        // the consensus set
        if stake == token::Amount::default() {
            continue;
        }

        let mut rewards_frac = Dec::zero();
        let stake_unscaled: Dec = stake.into();
        // println!(
        //     "NAMADA VALIDATOR STAKE (LOGGING BLOCK REWARDS) OF EPOCH {} =
        // {}",     epoch, stake
        // );

        // Proposer reward
        if address == *proposer_address {
            rewards_frac += coeffs.proposer_coeff;
        }
        // Signer reward
        if signer_set.contains(&address) {
            let signing_frac = stake_unscaled / signing_stake_unscaled;
            rewards_frac += coeffs.signer_coeff * signing_frac;
        }
        // Consensus validator reward
        rewards_frac += coeffs.active_val_coeff
            * (stake_unscaled / consensus_stake_unscaled);

        // Update the rewards accumulator
        let prev = rewards_accumulator_handle()
            .get(storage, &address)?
            .unwrap_or_default();
        values.insert(address, prev + rewards_frac);
    }
    for (address, value) in values.into_iter() {
        rewards_accumulator_handle().insert(storage, address, value)?;
    }

    Ok(())
}

/// Calculate the cubic slashing rate using all slashes within a window around
/// the given infraction epoch. There is no cap on the rate applied within this
/// function.
pub fn compute_cubic_slash_rate<S>(
    storage: &S,
    params: &PosParams,
    infraction_epoch: Epoch,
) -> storage_api::Result<Dec>
where
    S: StorageRead,
{
    // println!("COMPUTING CUBIC SLASH RATE");
    let mut sum_vp_fraction = Dec::zero();
    let (start_epoch, end_epoch) =
        params.cubic_slash_epoch_window(infraction_epoch);

    for epoch in Epoch::iter_bounds_inclusive(start_epoch, end_epoch) {
        let consensus_stake =
            Dec::from(get_total_consensus_stake(storage, epoch, params)?);
        tracing::debug!(
            "Total consensus stake in epoch {}: {}",
            epoch,
            consensus_stake
        );
        let processing_epoch = epoch + params.slash_processing_epoch_offset();
        let slashes = enqueued_slashes_handle().at(&processing_epoch);
        let infracting_stake = slashes.iter(storage)?.fold(
            Ok(Dec::zero()),
            |acc: storage_api::Result<Dec>, res| {
                let acc = acc?;
                let (
                    NestedSubKey::Data {
                        key: validator,
                        nested_sub_key: _,
                    },
                    _slash,
                ) = res?;

                let validator_stake =
                    read_validator_stake(storage, params, &validator, epoch)?
                        .unwrap_or_default();
                // println!("Val {} stake: {}", &validator, validator_stake);

                Ok(acc + Dec::from(validator_stake))
                // TODO: does something more complex need to be done
                // here in the event some of these slashes correspond to
                // the same validator?
            },
        )?;
        sum_vp_fraction += infracting_stake / consensus_stake;
    }
    // println!("sum_vp_fraction: {}", sum_vp_fraction);
    Ok(Dec::new(9, 0).unwrap() * sum_vp_fraction * sum_vp_fraction)
}

/// Record a slash for a misbehavior that has been received from Tendermint and
/// then jail the validator, removing it from the validator set. The slash rate
/// will be computed at a later epoch.
#[allow(clippy::too_many_arguments)]
pub fn slash<S>(
    storage: &mut S,
    params: &PosParams,
    current_epoch: Epoch,
    evidence_epoch: Epoch,
    evidence_block_height: impl Into<u64>,
    slash_type: SlashType,
    validator: &Address,
    validator_set_update_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let evidence_block_height: u64 = evidence_block_height.into();
    let slash = Slash {
        epoch: evidence_epoch,
        block_height: evidence_block_height,
        r#type: slash_type,
        rate: Dec::zero(), // Let the rate be 0 initially before processing
    };
    // Need `+1` because we process at the beginning of a new epoch
    let processing_epoch =
        evidence_epoch + params.slash_processing_epoch_offset();
    let pipeline_epoch = current_epoch + params.pipeline_len;

    // Add the slash to the list of enqueued slashes to be processed at a later
    // epoch
    enqueued_slashes_handle()
        .get_data_handler()
        .at(&processing_epoch)
        .at(validator)
        .push(storage, slash)?;

    // Update the most recent slash (infraction) epoch for the validator
    let last_slash_epoch = read_validator_last_slash_epoch(storage, validator)?;
    if last_slash_epoch.is_none()
        || evidence_epoch.0 > last_slash_epoch.unwrap_or_default().0
    {
        write_validator_last_slash_epoch(storage, validator, evidence_epoch)?;
    }

    // Remove the validator from the set starting at the next epoch and up thru
    // the pipeline epoch.
    for epoch in
        Epoch::iter_bounds_inclusive(validator_set_update_epoch, pipeline_epoch)
    {
        let prev_state = validator_state_handle(validator)
            .get(storage, epoch, params)?
            .expect("Expected to find a valid validator.");
        match prev_state {
            ValidatorState::Consensus => {
                let amount_pre = validator_deltas_handle(validator)
                    .get_sum(storage, epoch, params)?
                    .unwrap_or_default();
                let val_position = validator_set_positions_handle()
                    .at(&epoch)
                    .get(storage, validator)?
                    .expect("Could not find validator's position in storage.");
                let _ = consensus_validator_set_handle()
                    .at(&epoch)
                    .at(&token::Amount::from_change(amount_pre))
                    .remove(storage, &val_position)?;
                validator_set_positions_handle()
                    .at(&epoch)
                    .remove(storage, validator)?;

                // For the pipeline epoch only:
                // promote the next max inactive validator to the active
                // validator set at the pipeline offset
                if epoch == pipeline_epoch {
                    let below_capacity_handle =
                        below_capacity_validator_set_handle().at(&epoch);
                    let max_below_capacity_amount =
                        get_max_below_capacity_validator_amount(
                            &below_capacity_handle,
                            storage,
                        )?;
                    if let Some(max_below_capacity_amount) =
                        max_below_capacity_amount
                    {
                        let position_to_promote = find_first_position(
                            &below_capacity_handle
                                .at(&max_below_capacity_amount.into()),
                            storage,
                        )?
                        .expect("Should return a position.");
                        let max_bc_validator = below_capacity_handle
                            .at(&max_below_capacity_amount.into())
                            .remove(storage, &position_to_promote)?
                            .expect(
                                "Should have returned a removed validator.",
                            );
                        insert_validator_into_set(
                            &consensus_validator_set_handle()
                                .at(&epoch)
                                .at(&max_below_capacity_amount),
                            storage,
                            &epoch,
                            &max_bc_validator,
                        )?;
                        validator_state_handle(&max_bc_validator).set(
                            storage,
                            ValidatorState::Consensus,
                            current_epoch,
                            params.pipeline_len,
                        )?;
                    }
                }
            }
            ValidatorState::BelowCapacity => {
                let amount_pre = validator_deltas_handle(validator)
                    .get_sum(storage, epoch, params)?
                    .unwrap_or_default();
                let val_position = validator_set_positions_handle()
                    .at(&epoch)
                    .get(storage, validator)?
                    .expect("Could not find validator's position in storage.");
                let _ = below_capacity_validator_set_handle()
                    .at(&epoch)
                    .at(&token::Amount::from_change(amount_pre).into())
                    .remove(storage, &val_position)?;
                validator_set_positions_handle()
                    .at(&epoch)
                    .remove(storage, validator)?;
            }
            ValidatorState::BelowThreshold => {
                println!("Below-threshold");
            }
            ValidatorState::Inactive => {
                println!("INACTIVE");
                panic!(
                    "Shouldn't be here - haven't implemented inactive vals yet"
                )
            }
            ValidatorState::Jailed => {
                tracing::debug!(
                    "Found evidence for a validator who is already jailed"
                );
                // return Ok(());
            }
        }
    }
    // Safe sub cause `validator_set_update_epoch > current_epoch`
    let start_offset = validator_set_update_epoch.0 - current_epoch.0;
    // Set the validator state as `Jailed` thru the pipeline epoch
    for offset in start_offset..=params.pipeline_len {
        validator_state_handle(validator).set(
            storage,
            ValidatorState::Jailed,
            current_epoch,
            offset,
        )?;
    }

    // No other actions are performed here until the epoch in which the slash is
    // processed.

    Ok(())
}

/// Process slashes NEW
pub fn process_slashes<S>(
    storage: &mut S,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let params = read_pos_params(storage)?;

    if current_epoch.0 < params.slash_processing_epoch_offset() {
        return Ok(());
    }
    let infraction_epoch =
        current_epoch - params.slash_processing_epoch_offset();

    // Slashes to be processed in the current epoch
    let enqueued_slashes = enqueued_slashes_handle().at(&current_epoch);
    if enqueued_slashes.is_empty(storage)? {
        return Ok(());
    }
    tracing::debug!(
        "Processing slashes at the beginning of epoch {} (committed in epoch \
         {})",
        current_epoch,
        infraction_epoch
    );

    // Compute the cubic slash rate
    let cubic_slash_rate =
        compute_cubic_slash_rate(storage, &params, infraction_epoch)?;

    // Collect the enqueued slashes and update their rates
    let mut eager_validator_slashes: HashMap<Address, Vec<Slash>> =
        HashMap::new(); // TODO: will need to update this in storage later
    let mut eager_validator_slash_rates: HashMap<Address, Dec> = HashMap::new();

    // `slashPerValidator` and `slashesMap` while also updating in storage
    for enqueued_slash in enqueued_slashes.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: validator,
                nested_sub_key: _,
            },
            enqueued_slash,
        ) = enqueued_slash?;
        debug_assert_eq!(enqueued_slash.epoch, infraction_epoch);

        let slash_rate = cmp::min(
            Dec::one(),
            cmp::max(
                enqueued_slash.r#type.get_slash_rate(&params),
                cubic_slash_rate,
            ),
        );
        let updated_slash = Slash {
            epoch: enqueued_slash.epoch,
            block_height: enqueued_slash.block_height,
            r#type: enqueued_slash.r#type,
            rate: slash_rate,
        };
        tracing::debug!(
            "Slash for validator {} committed in epoch {} has rate {}",
            &validator,
            enqueued_slash.epoch,
            slash_rate
        );

        let cur_slashes = eager_validator_slashes
            .entry(validator.clone())
            .or_default();
        cur_slashes.push(updated_slash);
        let cur_rate =
            eager_validator_slash_rates.entry(validator).or_default();
        *cur_rate = cmp::min(Dec::one(), *cur_rate + slash_rate);
    }

    // `resultSlashing`
    // TODO: check carefully that this is consistent
    let mut map_validator_slash: BTreeMap<
        Address,
        BTreeMap<Epoch, token::Change>,
    > = BTreeMap::new();
    for (validator, slash_rate) in eager_validator_slash_rates {
        process_validator_slash(
            storage,
            &params,
            &validator,
            slash_rate,
            current_epoch,
            &mut map_validator_slash,
        )?;
    }

    // Update the remaining parts of storage
    // TODO: why does it seem like we are updating epoched data for epochs
    // starting at cur - unbonding - cubic_offste + 1???

    Ok(())
}

/// Quint `processSlash`
fn process_validator_slash<S>(
    storage: &mut S,
    params: &PosParams,
    validator: &Address,
    slash_rate: Dec,
    current_epoch: Epoch,
    slashed_amount_map: &mut EagerRedelegatedBondsMap,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    // `resultSlashValidator
    let result_slash = slash_validator(
        storage,
        params,
        validator,
        slash_rate,
        current_epoch,
        &slashed_amount_map
            .get(validator)
            .cloned()
            .unwrap_or_default(),
    )?;

    // `updatedSlashedAmountMap`
    slashed_amount_map
        .entry(validator.clone())
        .or_insert(result_slash);

    // `outgoingRedelegation`
    let outgoing_redelegations =
        validator_outgoing_redelegations_handle(validator);

    // Final loop in `processSlash`
    let dest_validators = outgoing_redelegations
        .iter(storage)?
        .map(|res| {
            let (
                NestedSubKey::Data {
                    key: dest_validator,
                    nested_sub_key: _,
                },
                _redelegation,
            ) = res?;
            Ok(dest_validator)
        })
        .collect::<storage_api::Result<HashSet<_>>>()?;

    for dest_validator in dest_validators {
        let to_modify = slashed_amount_map
            .entry(dest_validator.clone())
            .or_default();

        // `slashValidatorRedelegation`
        slash_validator_redelegation(
            storage,
            params,
            validator,
            current_epoch,
            &outgoing_redelegations.at(&dest_validator),
            &validator_slashes_handle(validator),
            &validator_total_redelegated_unbonded_handle(&dest_validator),
            slash_rate,
            to_modify,
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn slash_validator_redelegation<S>(
    storage: &S,
    params: &PosParams,
    src_validator: &Address,
    current_epoch: Epoch,
    outgoing_redelegations: &NestedMap<Epoch, LazyMap<Epoch, token::Amount>>,
    slashes: &Slashes,
    dest_total_redelegated_unbonded: &TotalRedelegatedUnbonded,
    slash_rate: Dec,
    dest_slashed_amounts: &mut BTreeMap<Epoch, token::Change>,
) -> storage_api::Result<()>
where
    S: StorageRead,
{
    let infraction_epoch =
        current_epoch - params.slash_processing_epoch_offset();

    for res in outgoing_redelegations.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: bond_start,
                nested_sub_key: SubKey::Data(redel_start),
            },
            amount,
        ) = res?;
        if params.in_redelegation_slashing_window(
            infraction_epoch,
            redel_start,
            params.redelegation_end_epoch_from_start(redel_start),
        ) && bond_start <= infraction_epoch
        {
            slash_redelegation(
                storage,
                params,
                amount.change(),
                bond_start,
                params.redelegation_end_epoch_from_start(redel_start),
                src_validator,
                current_epoch,
                slashes,
                dest_total_redelegated_unbonded,
                slash_rate,
                dest_slashed_amounts,
            )?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn slash_redelegation<S>(
    storage: &S,
    params: &PosParams,
    amount: token::Change,
    bond_start: Epoch,
    redel_bond_start: Epoch,
    src_validator: &Address,
    current_epoch: Epoch,
    slashes: &Slashes,
    total_redelegated_unbonded: &TotalRedelegatedUnbonded,
    slash_rate: Dec,
    slashed_amounts: &mut BTreeMap<Epoch, token::Change>,
) -> storage_api::Result<()>
where
    S: StorageRead,
{
    let infraction_epoch =
        current_epoch - params.slash_processing_epoch_offset();

    let amountless_redelegation = Redelegation {
        bond_start,
        src_validator: src_validator.clone(),
        redel_bond_start,
        amount: Default::default(),
    };

    let mut init_tot_unbonded =
        Epoch::iter_bounds_inclusive(infraction_epoch.next(), current_epoch)
            .fold(token::Change::zero(), |acc, epoch| {
                if !has_redelegation(
                    storage,
                    &total_redelegated_unbonded.at(&epoch),
                    &amountless_redelegation,
                )
                .unwrap()
                {
                    acc
                } else {
                    acc + total_redelegated_unbonded
                        .at(&epoch)
                        .at(&redel_bond_start)
                        .at(src_validator)
                        .get(storage, &bond_start)
                        .unwrap()
                        .unwrap_or_default()
                }
            });

    for epoch in Epoch::iter_bounds_inclusive(
        current_epoch.next(),
        current_epoch + params.pipeline_len,
    ) {
        let updated_total_unbonded = if has_redelegation(
            storage,
            &total_redelegated_unbonded.at(&epoch),
            &amountless_redelegation,
        )
        .unwrap()
        {
            init_tot_unbonded
        } else {
            init_tot_unbonded
                + total_redelegated_unbonded
                    .at(&epoch)
                    .at(&redel_bond_start)
                    .at(src_validator)
                    .get(storage, &bond_start)
                    .unwrap()
                    .unwrap_or_default()
        };
        let list_slashes = slashes
            .iter(storage)?
            .map(Result::unwrap)
            .filter(|slash| {
                // TODO: check bounds!!
                params.in_redelegation_slashing_window(
                    slash.epoch,
                    params.redelegation_start_epoch_from_end(redel_bond_start),
                    redel_bond_start,
                ) && bond_start <= slash.epoch
                    && slash.epoch + params.slash_processing_epoch_offset()
                        < infraction_epoch
            })
            .collect::<Vec<_>>();

        let slashed = slash_rate
            * apply_list_slashes(
                params,
                &list_slashes,
                amount - updated_total_unbonded,
            );

        let list_slashes = slashes
            .iter(storage)?
            .map(Result::unwrap)
            .filter(|slash| {
                // TODO: check bounds!!
                params.in_redelegation_slashing_window(
                    slash.epoch,
                    params.redelegation_start_epoch_from_end(redel_bond_start),
                    redel_bond_start,
                ) && bond_start <= slash.epoch
            })
            .collect::<Vec<_>>();

        let slashable_stake = slash_rate
            * apply_list_slashes(
                params,
                &list_slashes,
                amount - updated_total_unbonded,
            );

        init_tot_unbonded = updated_total_unbonded;
        let map_value = slashed_amounts.entry(epoch).or_default();
        *map_value += cmp::min(slashed, slashable_stake).change();
    }

    Ok(())
}

fn slash_validator<S>(
    storage: &mut S,
    params: &PosParams,
    validator: &Address,
    slash_rate: Dec,
    current_epoch: Epoch,
    slashed_amounts_map: &BTreeMap<Epoch, token::Change>,
) -> storage_api::Result<BTreeMap<Epoch, token::Change>>
where
    S: StorageRead,
{
    let infraction_epoch =
        current_epoch - params.slash_processing_epoch_offset();

    let infraction_stake = validator_deltas_handle(validator)
        .get_sum(storage, infraction_epoch, params)?
        .unwrap_or_default();

    let total_unbonded = unbond_records_handle(validator);
    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(validator);
    let total_bonded = total_bonded_handle(validator);
    let total_redelegated_bonded =
        validator_total_redelegated_bonded_handle(validator);

    let mut init_total_unbonded = token::Change::default();
    let mut init_bond_balance = token::Change::default();
    let mut init_redelegated_bond_balance =
        BTreeMap::<Epoch, token::Change>::new();
    for epoch in
        Epoch::iter_bounds_inclusive(infraction_epoch.next(), current_epoch)
    {
        init_total_unbonded += compute_total_unbonded(
            storage,
            params,
            validator,
            infraction_epoch,
            &total_unbonded.at(&epoch),
            &total_redelegated_unbonded.at(&epoch),
        )?;
        init_bond_balance += total_bonded
            .get_delta_val(storage, epoch)?
            .unwrap_or_default()
            - compute_recent_total_unbonded(
                storage,
                infraction_epoch,
                &total_unbonded.at(&epoch),
                &total_redelegated_unbonded.at(&epoch),
            )
            .unwrap_or_default();
        // Choosing to do this by mutating the existing map
        compute_redelegated_bonds_balance(
            storage,
            params,
            epoch,
            current_epoch,
            &total_redelegated_bonded.at(&epoch),
            &total_redelegated_unbonded,
            &mut init_redelegated_bond_balance,
        )?;
    }

    let mut slashed_amounts = slashed_amounts_map.clone();
    for epoch in Epoch::iter_bounds_inclusive(
        current_epoch.next(),
        current_epoch + params.pipeline_len,
    ) {
        let updated_total_unbonded = init_total_unbonded
            + compute_total_unbonded(
                storage,
                params,
                validator,
                infraction_epoch,
                &total_unbonded.at(&epoch),
                &total_redelegated_unbonded.at(&epoch),
            )?;
        let updated_bonds_balance = dbg!(init_bond_balance)
            + dbg!(
                total_bonded
                    .get_delta_val(storage, epoch)?
                    .unwrap_or_default()
            )
            - dbg!(compute_recent_total_unbonded(
                storage,
                infraction_epoch,
                &total_unbonded.at(&epoch),
                &total_redelegated_unbonded.at(&epoch),
            ))?;
        compute_redelegated_bonds_balance(
            storage,
            params,
            epoch,
            current_epoch,
            &total_redelegated_bonded.at(&epoch),
            &total_redelegated_unbonded,
            &mut init_redelegated_bond_balance,
        )?;

        let slashed_amount =
            slash_rate * (infraction_stake - updated_total_unbonded);
        let current_stake = validator_deltas_handle(validator)
            .get_sum(storage, epoch, params)?
            .unwrap_or_default()
            - slashed_amounts.get(&epoch).cloned().unwrap_or_default();

        let slashable_stake = current_stake
            - updated_bonds_balance
            - init_redelegated_bond_balance
                .get(&epoch)
                .cloned()
                .unwrap_or_default();

        let cur_amount = slashed_amounts.entry(epoch).or_default();
        *cur_amount += cmp::min(slashed_amount, slashable_stake);

        init_total_unbonded = updated_total_unbonded;
        init_bond_balance = updated_bonds_balance;

    }

    Ok(slashed_amounts)
}

fn compute_redelegated_bonds_balance<S>(
    storage: &S,
    params: &PosParams,
    redel_bond_start: Epoch,
    current_epoch: Epoch,
    total_redelegated_bonded: &NestedMap<
        Address,
        LazyMap<Epoch, token::Change>,
    >,
    total_redelegated_unbonded: &TotalRedelegatedUnbonded,
    cur_balance_map: &mut BTreeMap<Epoch, token::Change>,
) -> storage_api::Result<()>
where
    S: StorageRead,
{
    total_redelegated_bonded.iter(storage)?.for_each(|a| {
        let (
            NestedSubKey::Data {
                key: src_validator,
                nested_sub_key: SubKey::Data(bond_start),
            },
            amount,
        ) = a.unwrap();
        let redelegation = Redelegation {
            redel_bond_start,
            src_validator,
            bond_start,
            amount,
        };
        compute_remainder_redelegation(
            storage,
            params,
            &redelegation,
            current_epoch,
            &validator_slashes_handle(&redelegation.src_validator),
            total_redelegated_unbonded,
            cur_balance_map,
        )
        .expect("Failed to compute redelegation remainder");
    });
    Ok(())
}

/// `computeRemainderRedelegationTest`
fn compute_remainder_redelegation<S>(
    storage: &S,
    params: &PosParams,
    redelegation: &Redelegation,
    current_epoch: Epoch,
    slashes: &Slashes,
    total_redelegated_unbonded: &TotalRedelegatedUnbonded,
    cur_balance_map: &mut BTreeMap<Epoch, token::Change>,
) -> storage_api::Result<()>
where
    S: StorageRead,
{
    let mut total = token::Change::default();
    for epoch in Epoch::iter_bounds_inclusive(
        redelegation.redel_bond_start,
        current_epoch + params.pipeline_len,
    ) {
        let updated_total_unbonded = if !has_redelegation(
            storage,
            &total_redelegated_unbonded.at(&epoch),
            redelegation,
        )? {
            total
        } else {
            total
                + total_redelegated_unbonded
                    .at(&epoch)
                    .at(&redelegation.redel_bond_start)
                    .at(&redelegation.src_validator)
                    .get(storage, &redelegation.bond_start)?
                    .unwrap_or_default()
        };
        // TODO: check this epoch constraint!!
        if epoch <= current_epoch {
            total = updated_total_unbonded;
        } else {
            let list_slashes = slashes
                .iter(storage)?
                .map(Result::unwrap)
                .filter(|slash| {
                    params.in_redelegation_slashing_window(
                        slash.epoch,
                        params.redelegation_start_epoch_from_end(
                            redelegation.redel_bond_start,
                        ),
                        redelegation.redel_bond_start,
                    ) && redelegation.bond_start <= slash.epoch
                })
                .collect::<Vec<_>>();
            let stake_left = apply_list_slashes(
                params,
                &list_slashes,
                redelegation.amount - updated_total_unbonded,
            );
            total = updated_total_unbonded;
            let cur_bal = cur_balance_map.entry(epoch).or_default();
            *cur_bal += stake_left.change();
        }
    }
    Ok(())
}

fn has_redelegation<S>(
    storage: &S,
    redelegations: &NestedMap<
        Epoch,
        NestedMap<Address, LazyMap<Epoch, token::Change>>,
    >,
    redelegation: &Redelegation,
) -> storage_api::Result<bool>
where
    S: StorageRead,
{
    Ok(redelegations
        .at(&redelegation.redel_bond_start)
        .at(&redelegation.src_validator)
        .get(storage, &redelegation.bond_start)?
        .is_some())
}

fn compute_recent_total_unbonded<S>(
    storage: &S,
    infraction_epoch: Epoch,
    total_unbonded: &LazyMap<Epoch, token::Amount>,
    total_redelegated_unbonded: &NestedMap<
        Epoch,
        NestedMap<Address, LazyMap<Epoch, token::Change>>,
    >,
) -> storage_api::Result<token::Change>
where
    S: StorageRead,
{
    total_unbonded.iter(storage)?.fold(
        storage_api::Result::Ok(token::Change::zero()),
        |acc, unbonds| {
            let (epoch, unbonded) = unbonds?;
            let unbonded = unbonded.change();
            if epoch > infraction_epoch && unbonded > token::Change::default() {
                let redel_unbonds = total_redelegated_unbonded.at(&epoch);
                let non_redelegated_amount = if !redel_unbonds
                    .is_empty(storage)?
                {
                    total_unbonded
                        .get(storage, &epoch)?
                        .unwrap_or_default()
                        .change()
                        - fold_redelegated_bonds_map(storage, &redel_unbonds)?
                } else {
                    total_unbonded
                        .get(storage, &epoch)?
                        .unwrap_or_default()
                        .change()
                };
                Ok(acc? + non_redelegated_amount)
            } else {
                acc
            }
        },
    )
}

fn fold_redelegated_bonds_map<S>(
    storage: &S,
    redelegated_bonds: &NestedMap<Address, LazyMap<Epoch, token::Change>>,
) -> storage_api::Result<token::Change>
where
    S: StorageRead,
{
    redelegated_bonds.iter(storage)?.fold(
        Ok(token::Change::zero()),
        |acc, res| {
            let (_, amount) = res?;
            Ok(acc? + amount)
        },
    )
}

fn compute_total_unbonded<S>(
    storage: &S,
    params: &PosParams,
    validator: &Address,
    infraction_epoch: Epoch,
    total_unbonded: &LazyMap<Epoch, token::Amount>,
    total_redelegated_unbonded: &NestedMap<
        Epoch,
        NestedMap<Address, LazyMap<Epoch, token::Change>>,
    >,
) -> storage_api::Result<token::Change>
where
    S: StorageRead,
{
    // let eager_tot_unbonded = total_unbonded.collect_map(storage)?;
    // let eager_tot_redelegated_unbonded =
    //     total_redelegated_unbonded.collect_map(storage)?;

    // dbg!(&eager_tot_unbonded);
    // dbg!(&eager_tot_redelegated_unbonded);

    let total = total_unbonded
        .iter(storage)?
        .map(Result::unwrap)
        .filter(|&(epoch, _)| epoch <= infraction_epoch)
        .fold(token::Change::zero(), |acc, (epoch, _amount)| {
            // `listSlashes`
            let list_slashes = validator_slashes_handle(validator)
                .iter(storage)
                .unwrap()
                .map(Result::unwrap)
                .filter(|s| {
                    // TODO: check bounds!
                    epoch <= s.epoch
                        // slashes that have already been applied and processed
                        && s.epoch + params.slash_processing_epoch_offset()
                            <= infraction_epoch
                })
                .collect::<Vec<_>>();

            // dbg!(&list_slashes);

            let tot_redelegated_unbonded =
                total_redelegated_unbonded.at(&epoch);

            let result_fold =
                if !tot_redelegated_unbonded.is_empty(storage).unwrap() {
                    let redelegated_unbonds =
                        tot_redelegated_unbonded.collect_map(storage).unwrap();

                    // Used to accomplish `filteredSlashMap`
                    // slashes that have already been applied and processed
                    let slash_epoch_filter = |e: Epoch| {
                        e + params.slash_processing_epoch_offset()
                            <= infraction_epoch
                    };
                    fold_and_slash_redelegated_bonds(
                        storage,
                        params,
                        &redelegated_unbonds,
                        &infraction_epoch,
                        &list_slashes,
                        slash_epoch_filter,
                    )
                } else {
                    FoldRedelegatedBondsResult::default()
                };

            // dbg!(&result_fold);

            let total_not_redelegated = total_unbonded
                .get(storage, &epoch)
                .unwrap()
                .unwrap_or_default()
                - result_fold.total_redelegated;

            // dbg!(&total_not_redelegated);

            let after_not_redelegated = apply_list_slashes(
                params,
                &list_slashes,
                total_not_redelegated.change(),
            );
            // dbg!(&after_not_redelegated);

            let amount_after_slashing =
                after_not_redelegated + result_fold.total_after_slashing;

            // dbg!(&amount_after_slashing);
            // dbg!(acc + amount_after_slashing.change());

            acc + amount_after_slashing.change()
        });
    Ok(total)
}

/// Process slashes that have been queued up after discovery. Calculate the
/// cubic slashing rate, store the finalized slashes, update the deltas, then
/// transfer slashed tokens from PoS to the Slash Pool. This function is called
/// at the beginning of the epoch that is `unbonding_length + 1 +
/// cubic_slashing_window_length` epochs after the infraction epoch.
pub fn process_slashes_old<S>(
    storage: &mut S,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let params = read_pos_params(storage)?;

    if current_epoch.0 < params.slash_processing_epoch_offset() {
        return Ok(());
    }
    let infraction_epoch =
        current_epoch - params.slash_processing_epoch_offset();

    // Slashes to be processed in the current epoch
    let enqueued_slashes = enqueued_slashes_handle().at(&current_epoch);
    if enqueued_slashes.is_empty(storage)? {
        return Ok(());
    }
    tracing::debug!(
        "Processing slashes at the beginning of epoch {} (committed in epoch \
         {})",
        current_epoch,
        infraction_epoch
    );

    // Compute the cubic slash rate
    let cubic_slash_rate =
        compute_cubic_slash_rate(storage, &params, infraction_epoch)?;

    // Collect the enqueued slashes and update their rates
    let mut validators_and_slashes: HashMap<Address, Vec<Slash>> =
        HashMap::new();
    for enqueued_slash in enqueued_slashes.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: validator,
                nested_sub_key: _,
            },
            enqueued_slash,
        ) = enqueued_slash?;
        debug_assert_eq!(enqueued_slash.epoch, infraction_epoch);

        let slash_rate = cmp::min(
            Dec::one(),
            cmp::max(
                enqueued_slash.r#type.get_slash_rate(&params),
                cubic_slash_rate,
            ),
        );
        let updated_slash = Slash {
            epoch: enqueued_slash.epoch,
            block_height: enqueued_slash.block_height,
            r#type: enqueued_slash.r#type,
            rate: slash_rate,
        };
        tracing::debug!(
            "Slash for validator {} committed in epoch {} has rate {}",
            &validator,
            enqueued_slash.epoch,
            slash_rate
        );

        let cur_slashes = validators_and_slashes.entry(validator).or_default();
        cur_slashes.push(updated_slash);
    }

    let mut deltas_for_update: HashMap<Address, Vec<(u64, token::Change)>> =
        HashMap::new();

    // Store the final processed slashes to their corresponding validators, then
    // update the deltas
    for (validator, enqueued_slashes) in validators_and_slashes.into_iter() {
        let validator_stake_at_infraction = read_validator_stake(
            storage,
            &params,
            &validator,
            infraction_epoch,
        )?
        .unwrap_or_default();

        tracing::debug!(
            "Validator {} stake at infraction epoch {} = {}",
            &validator,
            infraction_epoch,
            validator_stake_at_infraction.to_string_native()
        );

        let mut total_rate = Dec::zero();

        for enqueued_slash in &enqueued_slashes {
            // Add this slash to the list of validator's slashes in storage
            validator_slashes_handle(&validator)
                .push(storage, enqueued_slash.clone())?;

            total_rate += enqueued_slash.rate;
        }
        total_rate = cmp::min(Dec::one(), total_rate);

        // Find the total amount deducted from the deltas due to unbonds that
        // became active after the infraction epoch, accounting for slashes
        let mut total_unbonded = token::Amount::default();

        let total_bonded_handle = total_bonded_handle(&validator);
        let mut sum_post_bonds = token::Change::default();

        // Start from after the infraction epoch up thru last epoch before
        // processing
        tracing::debug!("Iterating over unbonds after the infraction epoch");
        for epoch in Epoch::iter_bounds_inclusive(
            infraction_epoch.next(),
            current_epoch.prev(),
        ) {
            tracing::debug!("Epoch {}", epoch);
            let mut recent_unbonds = token::Change::default();
            let unbonds = unbond_records_handle(&validator).at(&epoch);
            for unbond in unbonds.iter(storage)? {
                let (start, unbond_amount) = unbond?;
                tracing::debug!(
                    "UnbondRecord: amount = {}, start_epoch {}",
                    unbond_amount.to_string_native(),
                    &start
                );
                if start <= infraction_epoch {
                    let prev_slashes = find_slashes_in_range(
                        storage,
                        start,
                        Some(
                            infraction_epoch
                                .checked_sub(Epoch(
                                    params.unbonding_len
                                        + params.cubic_slashing_window_length,
                                ))
                                .unwrap_or_default(),
                        ),
                        &validator,
                    )?;
                    tracing::debug!(
                        "Slashes for this unbond: {:?}",
                        prev_slashes
                    );

                    total_unbonded +=
                        token::Amount::from_change(get_slashed_amount(
                            &params,
                            unbond_amount,
                            &prev_slashes,
                        )?);
                } else {
                    recent_unbonds += unbond_amount.change();
                }

                tracing::debug!(
                    "Total unbonded (epoch {}) w slashing = {}",
                    epoch,
                    total_unbonded.to_string_native()
                );
            }

            sum_post_bonds += total_bonded_handle
                .get_delta_val(storage, epoch)?
                .unwrap_or_default()
                - recent_unbonds;
        }

        // Compute the adjusted validator deltas and slashed amounts from the
        // current up until the pipeline epoch
        let mut last_slash = token::Change::default();
        for offset in 0..params.pipeline_len {
            tracing::debug!(
                "Epoch {}\nLast slash = {}",
                current_epoch + offset,
                last_slash.to_string_native()
            );
            let mut recent_unbonds = token::Change::default();
            let unbonds =
                unbond_records_handle(&validator).at(&(current_epoch + offset));

            for unbond in unbonds.iter(storage)? {
                let (start, unbond_amount) = unbond?;
                tracing::debug!(
                    "UnbondRecord: amount = {}, start_epoch {}",
                    unbond_amount.to_string_native(),
                    &start
                );
                if start <= infraction_epoch {
                    let prev_slashes = find_slashes_in_range(
                        storage,
                        start,
                        Some(
                            infraction_epoch
                                .checked_sub(Epoch(
                                    params.unbonding_len
                                        + params.cubic_slashing_window_length,
                                ))
                                .unwrap_or_default(),
                        ),
                        &validator,
                    )?;
                    tracing::debug!(
                        "Slashes for this unbond: {:?}",
                        prev_slashes
                    );

                    total_unbonded +=
                        token::Amount::from_change(get_slashed_amount(
                            &params,
                            unbond_amount,
                            &prev_slashes,
                        )?);
                } else {
                    recent_unbonds += unbond_amount.change();
                }

                tracing::debug!(
                    "Total unbonded (offset {}) w slashing = {}",
                    offset,
                    total_unbonded.to_string_native()
                );
            }

            let this_slash = total_rate
                * (validator_stake_at_infraction - total_unbonded).change();
            let diff_slashed_amount = last_slash - this_slash;
            last_slash = this_slash;
            // println!("This slash = {}", this_slash);
            // println!("Diff slashed amount = {}", diff_slashed_amount);
            // total_slashed -= diff_slashed_amount;
            // total_unbonded = token::Amount::default();

            sum_post_bonds += total_bonded_handle
                .get_delta_val(storage, current_epoch + offset)?
                .unwrap_or_default()
                - recent_unbonds;

            let validator_stake_at_offset = read_validator_stake(
                storage,
                &params,
                &validator,
                current_epoch + offset,
            )?
            .unwrap_or_default()
            .change();
            let slashable_stake_at_offset =
                validator_stake_at_offset - sum_post_bonds;
            assert!(slashable_stake_at_offset >= token::Change::default());

            let change =
                cmp::max(-slashable_stake_at_offset, diff_slashed_amount);

            let val_updates =
                deltas_for_update.entry(validator.clone()).or_default();
            val_updates.push((offset, change));
        }
    }
    // println!("\nUpdating deltas");
    // Update the deltas in storage
    // let mut total_slashed = token::Change::default();
    for (validator, updates) in deltas_for_update {
        for (offset, delta) in updates {
            // println!("Val {}, offset {}, delta {}", &validator, offset,
            // delta);

            tracing::debug!(
                "Deltas change = {} at offset {} for validator {}",
                delta.to_string_native(),
                offset,
                &validator
            );
            // total_slashed -= change;

            update_validator_deltas(
                storage,
                &validator,
                delta,
                current_epoch,
                offset,
            )?;
            update_total_deltas(storage, delta, current_epoch, offset)?;
        }
    }

    // debug_assert!(total_slashed >= token::Change::default());

    // TODO: Transfer all slashed tokens from PoS account to Slash Pool address
    // let staking_token = staking_token_address(storage);
    // transfer_tokens(
    //     storage,
    //     &staking_token,
    //     token::Amount::from_change(total_slashed),
    //     &ADDRESS,
    //     &SLASH_POOL_ADDRESS,
    // )?;

    Ok(())
}

/// Unjail a validator that is currently jailed
pub fn unjail_validator<S>(
    storage: &mut S,
    validator: &Address,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let params = read_pos_params(storage)?;

    // Check that the validator is jailed up to the pipeline epoch
    for epoch in current_epoch.iter_range(params.pipeline_len + 1) {
        let state = validator_state_handle(validator).get(
            storage,
            current_epoch,
            &params,
        )?;
        if let Some(state) = state {
            if state != ValidatorState::Jailed {
                return Err(UnjailValidatorError::NotJailed(
                    validator.clone(),
                    epoch,
                )
                .into());
            }
        } else {
            return Err(
                UnjailValidatorError::NotAValidator(validator.clone()).into()
            );
        }
    }

    // Check that the unjailing tx can be submitted given the current epoch
    // and the most recent infraction epoch
    let last_slash_epoch = read_validator_last_slash_epoch(storage, validator)?
        .unwrap_or_default();
    let eligible_epoch =
        last_slash_epoch + params.slash_processing_epoch_offset();
    if current_epoch < eligible_epoch {
        return Err(UnjailValidatorError::NotEligible(
            validator.clone(),
            eligible_epoch,
            current_epoch,
        )
        .into());
    }
    // TODO: any other checks that are needed? (deltas, etc)?

    // Re-insert the validator into the validator set and update its state
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let stake =
        read_validator_stake(storage, &params, validator, pipeline_epoch)?
            .unwrap_or_default();

    insert_validator_into_validator_set(
        storage,
        &params,
        validator,
        stake,
        current_epoch,
        params.pipeline_len,
    )?;
    Ok(())
}

/// Check if a validator is frozen. A validator is frozen until after all of its
/// enqueued slashes have been processed, i.e. until `unbonding_len + 1 +
/// cubic_slashing_window_length` epochs after its most recent infraction epoch.
pub fn is_validator_frozen<S>(
    storage: &S,
    validator: &Address,
    current_epoch: Epoch,
    params: &PosParams,
) -> storage_api::Result<bool>
where
    S: StorageRead,
{
    let last_infraction_epoch =
        read_validator_last_slash_epoch(storage, validator)?;
    if let Some(last_epoch) = last_infraction_epoch {
        let is_frozen =
            current_epoch < last_epoch + params.slash_processing_epoch_offset();
        Ok(is_frozen)
    } else {
        Ok(false)
    }
}

fn get_total_consensus_stake<S>(
    storage: &S,
    epoch: Epoch,
    params: &PosParams,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    total_consensus_stake_key_handle()
        .get(storage, epoch, params)
        .map(|o| o.expect("Total consensus stake could not be retrieved."))
}

/// Find slashes applicable to a validator with inclusive `start` and exclusive
/// `end` epoch.
fn find_slashes_in_range<S>(
    storage: &S,
    start: Epoch,
    end: Option<Epoch>,
    validator: &Address,
) -> storage_api::Result<BTreeMap<Epoch, Dec>>
where
    S: StorageRead,
{
    let mut slashes = BTreeMap::<Epoch, Dec>::new();
    for slash in validator_slashes_handle(validator).iter(storage)? {
        let slash = slash?;
        if start <= slash.epoch
            && end.map(|end| slash.epoch < end).unwrap_or(true)
        {
            // println!(
            //     "Slash (epoch, rate) = ({}, {})",
            //     &slash.epoch, &slash.rate
            // );
            let cur_rate = slashes.entry(slash.epoch).or_default();
            *cur_rate = cmp::min(*cur_rate + slash.rate, Dec::one());
        }
    }
    Ok(slashes)
}

/// Redelegate bonded tokens from a source validator to a destination validator
pub fn redelegate_tokens<S>(
    storage: &mut S,
    owner: &Address,
    src_validator: &Address,
    dest_validator: &Address,
    current_epoch: Epoch,
    amount: token::Amount,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let params = read_pos_params(storage)?;
    let pipeline_epoch = current_epoch + params.pipeline_len;

    let redel_end_epoch =
        validator_incoming_redelegations_handle(src_validator)
            .get(storage, owner)?;
    let is_not_chained = if let Some(end_epoch) = redel_end_epoch {
        // TODO: check bounds for correctness (> and presence of cubic offset)
        end_epoch + params.unbonding_len > current_epoch
    } else {
        true
    };

    if !is_not_chained {
        return Err(RedelegationError::IsChainedRedelegation.into());
    }

    // TODO: the unbond fn itself needs to be updated for redelegation
    // `newDelegatorState` and `newSrcValidatorState` accounted for already
    let result_slashing = unbond_tokens(
        storage,
        Some(owner),
        src_validator,
        amount,
        current_epoch,
        true,
    )?;
    // `amountAfterSlashing`
    let amount_after_slashing = result_slashing.sum.change();

    // `updatedRedelegatedBonds` with updates to delegatorState
    // `redelegatedBonded`
    let existing = delegator_redelegated_bonds_handle(owner)
        .at(dest_validator)
        .at(&pipeline_epoch)
        .at(src_validator);
    let existing_iter = existing.iter(storage)?.map(Result::unwrap);

    let result_slashing_iter = result_slashing
        .epoch_map
        .iter()
        .map(|(epoch, amount)| (*epoch, amount.change()));

    let updated_redelegated_bonds =
        existing_iter.chain(result_slashing_iter).fold(
            BTreeMap::<Epoch, token::Change>::new(),
            |mut acc, (epoch, amount)| {
                let cur_val = acc.entry(epoch).or_default();
                *cur_val += amount;
                acc
            },
        );
    for (epoch, amount) in updated_redelegated_bonds.into_iter() {
        existing.insert(storage, epoch, amount)?;
    }

    // `updatedDelegator` with updates to `bonded`
    let bond_handle = bond_handle(owner, dest_validator);
    let cur_bond = bond_handle
        .get_delta_val(storage, pipeline_epoch)?
        .unwrap_or_default();
    bond_handle.set(
        storage,
        cur_bond + amount_after_slashing,
        current_epoch,
        params.pipeline_len,
    )?;

    // `updateOutgoingRedelegations` with `updatedSrcValidator`
    let outgoing_redelegations =
        validator_outgoing_redelegations_handle(src_validator)
            .at(dest_validator);
    let cur_outgoing_redelegations = outgoing_redelegations
        .iter(storage)?
        .map(|a| {
            let (
                NestedSubKey::Data {
                    key: start,
                    nested_sub_key: SubKey::Data(end),
                },
                amount,
            ) = a.unwrap();
            ((start, end), amount.change())
        })
        .collect::<BTreeMap<_, _>>();

    let new_epoch_map = result_slashing
        .epoch_map
        .iter()
        .map(|(epoch, amount)| (*epoch, amount.change()))
        .collect::<BTreeMap<_, _>>();

    let updated_outgoing_redelegations = merge_outgoing_redelegations(
        cur_outgoing_redelegations,
        new_epoch_map.clone(),
        current_epoch,
    );
    for ((start, end), amount) in updated_outgoing_redelegations.into_iter() {
        outgoing_redelegations.at(&start).insert(
            storage,
            end,
            token::Amount::from(amount),
        )?;
    }

    // `updatedDestValidator`
    // validator deltas
    update_validator_deltas(
        storage,
        dest_validator,
        amount_after_slashing,
        current_epoch,
        params.pipeline_len,
    )?;

    // validator total redelegated bonded
    let dest_total_redelegated_bonded =
        validator_total_redelegated_bonded_handle(dest_validator)
            .at(&pipeline_epoch);
    let src_bonds_from_slash =
        BTreeMap::from([(src_validator.clone(), new_epoch_map)]);
    let cur_total_redelegated_bonded =
        dest_total_redelegated_bonded.collect_map(storage)?;
    let new_total_redelegated_bonded = merge_redelegated_bonds_map(
        &cur_total_redelegated_bonded,
        &src_bonds_from_slash,
    );
    for (src_validator, bonds) in new_total_redelegated_bonded {
        for (epoch, amount) in bonds {
            dest_total_redelegated_bonded
                .at(&src_validator)
                .insert(storage, epoch, amount)?;
        }
    }

    // validator incoming redelegations
    let dest_incoming_redelegations =
        validator_incoming_redelegations_handle(dest_validator);
    dest_incoming_redelegations.insert(
        storage,
        owner.clone(),
        pipeline_epoch,
    )?;

    Ok(())
}

/// Merge outgoing redelegations given the existing ones and some new map of
/// bond deltas
fn merge_outgoing_redelegations(
    existing: BTreeMap<(Epoch, Epoch), token::Change>,
    new: BTreeMap<Epoch, token::Change>,
    current_epoch: Epoch,
) -> BTreeMap<(Epoch, Epoch), token::Change> {
    let transformed_new = new
        .into_iter()
        .map(|(epoch, amount)| ((epoch, current_epoch), amount));
    existing.into_iter().chain(transformed_new).fold(
        BTreeMap::<(Epoch, Epoch), token::Change>::new(),
        |mut acc, ((start_epoch, end_epoch), amount)| {
            let cur = acc.entry((start_epoch, end_epoch)).or_default();
            *cur += amount;
            acc
        },
    )
}
