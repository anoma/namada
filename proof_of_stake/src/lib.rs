//! Proof of Stake system.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

pub mod epoched;
pub mod parameters;
pub mod pos_queries;
pub mod rewards;
pub mod storage;
pub mod types;
// pub mod validation;

mod error;
#[cfg(test)]
mod tests;

use core::fmt::Debug;
use std::cmp::{self, Reverse};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use borsh::BorshDeserialize;
pub use error::*;
use namada_core::ledger::storage_api::collections::lazy_map::{
    Collectable, LazyMap, NestedMap, NestedSubKey, SubKey,
};
use namada_core::ledger::storage_api::collections::{LazyCollection, LazySet};
use namada_core::ledger::storage_api::{
    self, governance, token, ResultExt, StorageRead, StorageWrite,
};
use namada_core::types::address::{self, Address, InternalAddress};
use namada_core::types::dec::Dec;
use namada_core::types::key::{
    common, protocol_pk_key, tm_consensus_key_raw_hash, PublicKeyTmRawHash,
};
use namada_core::types::storage::BlockHeight;
pub use namada_core::types::storage::{Epoch, Key, KeySeg};
use once_cell::unsync::Lazy;
pub use parameters::{OwnedPosParams, PosParams};
use rewards::PosRewardsCalculator;
use storage::{
    bonds_for_source_prefix, bonds_prefix, consensus_keys_key,
    get_validator_address_from_bond, is_bond_key, is_unbond_key,
    is_validator_slashes_key, last_block_proposer_key,
    last_pos_reward_claim_epoch_key, params_key, rewards_counter_key,
    slashes_prefix, unbonds_for_source_prefix, unbonds_prefix,
    validator_address_raw_hash_key, validator_description_key,
    validator_discord_key, validator_email_key, validator_last_slash_key,
    validator_max_commission_rate_change_key, validator_website_key,
};
use types::{
    into_tm_voting_power, BelowCapacityValidatorSet,
    BelowCapacityValidatorSets, BondDetails, BondId, Bonds,
    BondsAndUnbondsDetail, BondsAndUnbondsDetails, CommissionRates,
    ConsensusValidator, ConsensusValidatorSet, ConsensusValidatorSets,
    DelegatorRedelegatedBonded, DelegatorRedelegatedUnbonded,
    EagerRedelegatedBondsMap, EpochedSlashes, IncomingRedelegations,
    LivenessMissedVotes, LivenessSumMissedVotes, OutgoingRedelegations,
    Position, RedelegatedBondsOrUnbonds, RedelegatedTokens,
    ReverseOrdTokenAmount, RewardsAccumulator, RewardsProducts, Slash,
    SlashType, SlashedAmount, Slashes, TotalConsensusStakes, TotalDeltas,
    TotalRedelegatedBonded, TotalRedelegatedUnbonded, UnbondDetails, Unbonds,
    ValidatorAddresses, ValidatorConsensusKeys, ValidatorDeltas,
    ValidatorEthColdKeys, ValidatorEthHotKeys, ValidatorMetaData,
    ValidatorPositionAddresses, ValidatorProtocolKeys, ValidatorSetPositions,
    ValidatorSetUpdate, ValidatorState, ValidatorStates,
    ValidatorTotalUnbonded, VoteInfo, WeightedValidator,
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

/// Get the storage handle to a PoS validator's protocol key key.
pub fn validator_protocol_key_handle(
    validator: &Address,
) -> ValidatorProtocolKeys {
    let key = protocol_pk_key(validator);
    ValidatorProtocolKeys::open(key)
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

/// Get the storage handle to a bond, which is dynamically updated with when
/// unbonding
pub fn bond_handle(source: &Address, validator: &Address) -> Bonds {
    let bond_id = BondId {
        source: source.clone(),
        validator: validator.clone(),
    };
    let key = storage::bond_key(&bond_id);
    Bonds::open(key)
}

/// Get the storage handle to a validator's total bonds, which are not updated
/// due to unbonding
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
pub fn total_unbonded_handle(validator: &Address) -> ValidatorTotalUnbonded {
    let key = storage::validator_total_unbonded_key(validator);
    ValidatorTotalUnbonded::open(key)
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

/// Get the storage handle to a validator's rewards products
pub fn validator_rewards_products_handle(
    validator: &Address,
) -> RewardsProducts {
    let key = storage::validator_rewards_product_key(validator);
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

/// Get the storage handle to the missed votes for liveness tracking
pub fn liveness_missed_votes_handle() -> LivenessMissedVotes {
    let key = storage::liveness_missed_votes_key();
    LivenessMissedVotes::open(key)
}

/// Get the storage handle to the sum of missed votes for liveness tracking
pub fn liveness_sum_missed_votes_handle() -> LivenessSumMissedVotes {
    let key = storage::liveness_sum_missed_votes_key();
    LivenessSumMissedVotes::open(key)
}

/// Init genesis. Requires that the governance parameters are initialized.
pub fn init_genesis<S>(
    storage: &mut S,
    params: &OwnedPosParams,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    tracing::debug!("Initializing PoS genesis");
    write_pos_params(storage, params)?;

    consensus_validator_set_handle().init(storage, current_epoch)?;
    below_capacity_validator_set_handle().init(storage, current_epoch)?;
    validator_set_positions_handle().init(storage, current_epoch)?;
    validator_addresses_handle().init(storage, current_epoch)?;
    tracing::debug!("Finished genesis");
    Ok(())
}

/// Copies the validator sets into all epochs up through the pipeline epoch at
/// genesis.
pub fn copy_genesis_validator_sets<S>(
    storage: &mut S,
    params: &OwnedPosParams,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let params = read_non_pos_owned_params(storage, params.clone())?;

    // Copy the genesis validator sets up to the pipeline epoch
    for epoch in (current_epoch.next()).iter_range(params.pipeline_len) {
        copy_validator_sets_and_positions(
            storage,
            &params,
            current_epoch,
            epoch,
        )?;
    }
    Ok(())
}

/// Read PoS parameters
pub fn read_pos_params<S>(storage: &S) -> storage_api::Result<PosParams>
where
    S: StorageRead,
{
    let params = storage
        .read(&params_key())
        .transpose()
        .expect("PosParams should always exist in storage after genesis")?;
    read_non_pos_owned_params(storage, params)
}

/// Read non-PoS-owned parameters to add them to `OwnedPosParams` to construct
/// `PosParams`.
pub fn read_non_pos_owned_params<S>(
    storage: &S,
    owned: OwnedPosParams,
) -> storage_api::Result<PosParams>
where
    S: StorageRead,
{
    let max_proposal_period = governance::get_max_proposal_period(storage)?;
    Ok(PosParams {
        owned,
        max_proposal_period,
    })
}

/// Write PoS parameters
pub fn write_pos_params<S>(
    storage: &mut S,
    params: &OwnedPosParams,
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
/// For non-validators and validators with `0` stake, this returns the default -
/// `token::Amount::zero()`.
pub fn read_validator_stake<S>(
    storage: &S,
    params: &PosParams,
    validator: &Address,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    let handle = validator_deltas_handle(validator);
    let amount = handle
        .get_sum(storage, epoch, params)?
        .map(|change| {
            debug_assert!(change.non_negative());
            token::Amount::from_change(change)
        })
        .unwrap_or_default();
    Ok(amount)
}

/// Add or remove PoS validator's stake delta value
pub fn update_validator_deltas<S>(
    storage: &mut S,
    params: &OwnedPosParams,
    validator: &Address,
    delta: token::Change,
    current_epoch: namada_core::types::storage::Epoch,
    offset_opt: Option<u64>,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let handle = validator_deltas_handle(validator);
    let offset = offset_opt.unwrap_or(params.pipeline_len);
    let val = handle
        .get_delta_val(storage, current_epoch + offset)?
        .unwrap_or_default();
    handle.set(
        storage,
        val.checked_add(&delta)
            .expect("Validator deltas updated amount should not overflow"),
        current_epoch,
        offset,
    )
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
        .map(|change| {
            debug_assert!(change.non_negative());
            token::Amount::from_change(change)
        })
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
    params: &OwnedPosParams,
    delta: token::Change,
    current_epoch: namada_core::types::storage::Epoch,
    offset_opt: Option<u64>,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let handle = total_deltas_handle();
    let offset = offset_opt.unwrap_or(params.pipeline_len);
    let val = handle
        .get_delta_val(storage, current_epoch + offset)?
        .unwrap_or_default();
    handle.set(
        storage,
        val.checked_add(&delta)
            .expect("Total deltas updated amount should not overflow"),
        current_epoch,
        offset,
    )
}

/// Check if the provided address is a validator address
pub fn is_validator<S>(
    storage: &S,
    address: &Address,
) -> storage_api::Result<bool>
where
    S: StorageRead,
{
    // TODO: should this check be made different? I suppose it does work but
    // feels weird...
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
    S: StorageRead,
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
        None => {
            let iter = storage_api::iter_prefix_bytes(storage, &prefix)?;
            for res in iter {
                let (key, _) = res?;
                if let Some((bond_id, _epoch)) = is_bond_key(&key) {
                    if bond_id.source != bond_id.validator {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
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
    offset_opt: Option<u64>,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    tracing::debug!(
        "Bonding token amount {} at epoch {current_epoch}",
        amount.to_string_native()
    );
    if amount.is_zero() {
        return Ok(());
    }

    // Transfer the bonded tokens from the source to PoS
    if let Some(source) = source {
        if source != validator && is_validator(storage, source)? {
            return Err(
                BondError::SourceMustNotBeAValidator(source.clone()).into()
            );
        }
    }
    let source = source.unwrap_or(validator);
    tracing::debug!("Source {source} --> Validator {validator}");

    let staking_token = staking_token_address(storage);
    token::transfer(storage, &staking_token, source, &ADDRESS, amount)?;

    let params = read_pos_params(storage)?;
    let offset = offset_opt.unwrap_or(params.pipeline_len);
    let offset_epoch = current_epoch + offset;

    // Check that the validator is actually a validator
    let validator_state_handle = validator_state_handle(validator);
    let state = validator_state_handle.get(storage, offset_epoch, &params)?;
    if state.is_none() {
        return Err(BondError::NotAValidator(validator.clone()).into());
    }

    let bond_handle = bond_handle(source, validator);
    let total_bonded_handle = total_bonded_handle(validator);

    if tracing::level_enabled!(tracing::Level::DEBUG) {
        let bonds = find_bonds(storage, source, validator)?;
        tracing::debug!("\nBonds before incrementing: {bonds:#?}");
    }

    // Initialize or update the bond at the pipeline offset
    bond_handle.add(storage, amount, current_epoch, offset)?;
    total_bonded_handle.add(storage, amount, current_epoch, offset)?;

    if tracing::level_enabled!(tracing::Level::DEBUG) {
        let bonds = find_bonds(storage, source, validator)?;
        tracing::debug!("\nBonds after incrementing: {bonds:#?}");
    }

    // Update the validator set
    // Allow bonding even if the validator is jailed. However, if jailed, there
    // must be no changes to the validator set. Check at the pipeline epoch.
    let is_jailed_or_inactive_at_pipeline = matches!(
        validator_state_handle.get(storage, offset_epoch, &params)?,
        Some(ValidatorState::Jailed) | Some(ValidatorState::Inactive)
    );
    if !is_jailed_or_inactive_at_pipeline {
        update_validator_set(
            storage,
            &params,
            validator,
            amount.change(),
            current_epoch,
            offset_opt,
        )?;
    }

    // Update the validator and total deltas
    update_validator_deltas(
        storage,
        &params,
        validator,
        amount.change(),
        current_epoch,
        offset_opt,
    )?;

    update_total_deltas(
        storage,
        &params,
        amount.change(),
        current_epoch,
        offset_opt,
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
    offset: Option<u64>,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    if token_change.is_zero() {
        return Ok(());
    }
    let offset = offset.unwrap_or(params.pipeline_len);
    let epoch = current_epoch + offset;
    tracing::debug!(
        "Update epoch for validator set: {epoch}, validator: {validator}"
    );
    let consensus_validator_set = consensus_validator_set_handle();
    let below_capacity_validator_set = below_capacity_validator_set_handle();

    // Validator sets at the pipeline offset
    let consensus_val_handle = consensus_validator_set.at(&epoch);
    let below_capacity_val_handle = below_capacity_validator_set.at(&epoch);

    let tokens_pre = read_validator_stake(storage, params, validator, epoch)?;

    let tokens_post = tokens_pre
        .change()
        .checked_add(&token_change)
        .expect("Post-validator set update token amount has overflowed");
    debug_assert!(tokens_post.non_negative());
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
    let position =
        read_validator_set_position(storage, validator, epoch, params)?;
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
                    offset,
                )?;

                // Remove the validator's position from storage
                validator_set_positions_handle()
                    .at(&epoch)
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
                        &epoch,
                        &removed_max_below_capacity,
                    )?;
                    validator_state_handle(&removed_max_below_capacity).set(
                        storage,
                        ValidatorState::Consensus,
                        current_epoch,
                        offset,
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
                    &epoch,
                    &removed_max_below_capacity,
                )?;
                validator_state_handle(&removed_max_below_capacity).set(
                    storage,
                    ValidatorState::Consensus,
                    current_epoch,
                    offset,
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
                    offset,
                )?;
            } else {
                tracing::debug!("Validator remains in consensus set");
                // The current validator should remain in the consensus set -
                // place it into a new position
                insert_validator_into_set(
                    &consensus_val_handle.at(&tokens_post),
                    storage,
                    &epoch,
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
                    validator,
                    tokens_post,
                    min_consensus_validator_amount,
                    current_epoch,
                    offset,
                    &consensus_val_handle,
                    &below_capacity_val_handle,
                )?;
            } else if tokens_post >= params.validator_stake_threshold {
                tracing::debug!("Validator remains in below-capacity set");
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
                    offset,
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
                    offset,
                )?;

                // Remove the validator's position from storage
                validator_set_positions_handle()
                    .at(&epoch)
                    .remove(storage, validator)?;
            }
        }
    } else {
        // At non-zero offset (0 is genesis only)
        if offset > 0 {
            // If there is no position at pipeline offset, then the validator
            // must be in the below-threshold set
            debug_assert!(tokens_pre < params.validator_stake_threshold);
        }
        tracing::debug!("Target validator is below-threshold");

        // Move the validator into the appropriate set
        let num_consensus_validators =
            get_num_consensus_validators(storage, epoch)?;
        if num_consensus_validators < params.max_validator_slots {
            // Just insert into the consensus set
            tracing::debug!("Inserting validator into the consensus set");

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
                offset,
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
                    validator,
                    tokens_post,
                    min_consensus_validator_amount,
                    current_epoch,
                    offset,
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
                    &epoch,
                    validator,
                )?;
                validator_state_handle(validator).set(
                    storage,
                    ValidatorState::BelowCapacity,
                    current_epoch,
                    offset,
                )?;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_into_consensus_and_demote_to_below_cap<S>(
    storage: &mut S,
    validator: &Address,
    tokens_post: token::Amount,
    min_consensus_amount: token::Amount,
    current_epoch: Epoch,
    offset: u64,
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

    let offset_epoch = current_epoch + offset;

    // Insert the min consensus validator into the below-capacity
    // set
    insert_validator_into_set(
        &below_capacity_set.at(&min_consensus_amount.into()),
        storage,
        &offset_epoch,
        &removed_min_consensus,
    )?;
    validator_state_handle(&removed_min_consensus).set(
        storage,
        ValidatorState::BelowCapacity,
        current_epoch,
        offset,
    )?;

    // Insert the current validator into the consensus set
    insert_validator_into_set(
        &consensus_set.at(&tokens_post),
        storage,
        &offset_epoch,
        validator,
    )?;
    validator_state_handle(validator).set(
        storage,
        ValidatorState::Consensus,
        current_epoch,
        offset,
    )?;
    Ok(())
}

/// Copy the consensus and below-capacity validator sets and positions into a
/// future epoch. Also copies the epoched set of all known validators in the
/// network.
pub fn copy_validator_sets_and_positions<S>(
    storage: &mut S,
    params: &PosParams,
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

    for ((val_stake, val_position), val_address) in consensus_in_mem.into_iter()
    {
        consensus_validator_set
            .at(&target_epoch)
            .at(&val_stake)
            .insert(storage, val_position, val_address)?;
    }

    for ((val_stake, val_position), val_address) in below_cap_in_mem.into_iter()
    {
        below_capacity_validator_set
            .at(&target_epoch)
            .at(&val_stake)
            .insert(storage, val_position, val_address)?;
    }
    // Purge consensus and below-capacity validator sets
    consensus_validator_set.update_data(storage, params, current_epoch)?;
    below_capacity_validator_set.update_data(storage, params, current_epoch)?;

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

    // Purge old epochs of validator positions
    validator_set_positions_handle.update_data(
        storage,
        params,
        current_epoch,
    )?;

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

    // Purge old epochs of all validator addresses
    validator_addresses_handle.update_data(storage, params, current_epoch)?;

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
            Ok(acc.checked_add(amount).expect(
                "Total consensus stake computation should not overflow.",
            ))
        })
}

/// Compute and then store the total consensus stake
pub fn compute_and_store_total_consensus_stake<S>(
    storage: &mut S,
    epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let total = compute_total_consensus_stake(storage, epoch)?;
    tracing::debug!(
        "Total consensus stake for epoch {}: {}",
        epoch,
        total.to_string_native()
    );
    total_consensus_stake_key_handle().set(storage, total, epoch, 0)
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

/// Temp: In quint this is from `ResultUnbondTx` field `resultSlashing: {sum:
/// int, epochMap: Epoch -> int}`
#[derive(Debug, Default)]
pub struct ResultSlashing {
    /// The token amount unbonded from the validator stake after accounting for
    /// slashes
    pub sum: token::Amount,
    /// Map from bond start epoch to token amount after slashing
    pub epoch_map: BTreeMap<Epoch, token::Amount>,
}

/// Unbond tokens that are bonded between a validator and a source (self or
/// delegator).
///
/// This fn is also called during redelegation for a source validator, in
/// which case the `is_redelegation` param must be true.
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
    if amount.is_zero() {
        return Ok(ResultSlashing::default());
    }

    let params = read_pos_params(storage)?;
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let withdrawable_epoch = current_epoch + params.withdrawable_epoch_offset();
    tracing::debug!(
        "Unbonding token amount {} at epoch {}, withdrawable at epoch {}",
        amount.to_string_native(),
        current_epoch,
        withdrawable_epoch
    );

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

    let source = source.unwrap_or(validator);
    let bonds_handle = bond_handle(source, validator);

    // Make sure there are enough tokens left in the bond at the pipeline offset
    let remaining_at_pipeline = bonds_handle
        .get_sum(storage, pipeline_epoch, &params)?
        .unwrap_or_default();
    if amount > remaining_at_pipeline {
        return Err(UnbondError::UnbondAmountGreaterThanBond(
            amount.to_string_native(),
            remaining_at_pipeline.to_string_native(),
        )
        .into());
    }

    if tracing::level_enabled!(tracing::Level::DEBUG) {
        let bonds = find_bonds(storage, source, validator)?;
        tracing::debug!("\nBonds before decrementing: {bonds:#?}");
    }

    let unbonds = unbond_handle(source, validator);

    let redelegated_bonds =
        delegator_redelegated_bonds_handle(source).at(validator);

    #[cfg(debug_assertions)]
    let redel_bonds_pre = redelegated_bonds.collect_map(storage)?;

    // `resultUnbonding`
    // Find the bonds to fully unbond (remove) and one to partially unbond, if
    // necessary
    let bonds_to_unbond = find_bonds_to_remove(
        storage,
        &bonds_handle.get_data_handler(),
        amount,
    )?;

    // `modifiedRedelegation`
    // A bond may have both redelegated and non-redelegated tokens in it. If
    // this is the case, compute the modified state of the redelegation.
    let modified_redelegation = match bonds_to_unbond.new_entry {
        Some((bond_epoch, new_bond_amount)) => {
            if redelegated_bonds.contains(storage, &bond_epoch)? {
                let cur_bond_amount = bonds_handle
                    .get_delta_val(storage, bond_epoch)?
                    .unwrap_or_default();
                compute_modified_redelegation(
                    storage,
                    &redelegated_bonds.at(&bond_epoch),
                    bond_epoch,
                    cur_bond_amount - new_bond_amount,
                )?
            } else {
                ModifiedRedelegation::default()
            }
        }
        None => ModifiedRedelegation::default(),
    };

    // Compute the new unbonds eagerly
    // `keysUnbonds`
    // Get a set of epochs from which we're unbonding (fully and partially).
    let bond_epochs_to_unbond =
        if let Some((start_epoch, _)) = bonds_to_unbond.new_entry {
            let mut to_remove = bonds_to_unbond.epochs.clone();
            to_remove.insert(start_epoch);
            to_remove
        } else {
            bonds_to_unbond.epochs.clone()
        };

    // `newUnbonds`
    // For each epoch we're unbonding, find the amount that's being unbonded.
    // For full unbonds, this is the current bond value. For partial unbonds
    // it is a difference between the current and new bond amount.
    let new_unbonds_map = bond_epochs_to_unbond
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
            (epoch, value)
        })
        .collect::<BTreeMap<Epoch, token::Amount>>();

    // `updatedBonded`
    // Remove bonds for all the full unbonds.
    for epoch in &bonds_to_unbond.epochs {
        bonds_handle.get_data_handler().remove(storage, epoch)?;
    }
    // Replace bond amount for partial unbond, if any.
    if let Some((bond_epoch, new_bond_amount)) = bonds_to_unbond.new_entry {
        bonds_handle.set(storage, new_bond_amount, bond_epoch, 0)?;
    }

    // `updatedUnbonded`
    // Update the unbonds in storage using the eager map computed above
    if !is_redelegation {
        for (start_epoch, &unbond_amount) in new_unbonds_map.iter() {
            unbonds.at(start_epoch).update(
                storage,
                withdrawable_epoch,
                |cur_val| cur_val.unwrap_or_default() + unbond_amount,
            )?;
        }
    }

    // `newRedelegatedUnbonds`
    // This is what the delegator's redelegated unbonds would look like if this
    // was the only unbond in the PoS system. We need to add these redelegated
    // unbonds to the existing redelegated unbonds
    let new_redelegated_unbonds = compute_new_redelegated_unbonds(
        storage,
        &redelegated_bonds,
        &bonds_to_unbond.epochs,
        &modified_redelegation,
    )?;

    // `updatedRedelegatedBonded`
    // NOTE: for now put this here after redelegated unbonds calc bc that one
    // uses the pre-modified redelegated bonds from storage!
    // First remove redelegation entries in epochs with full unbonds.
    for epoch_to_remove in &bonds_to_unbond.epochs {
        redelegated_bonds.remove_all(storage, epoch_to_remove)?;
    }
    if let Some(epoch) = modified_redelegation.epoch {
        tracing::debug!("\nIs modified redelegation");
        if modified_redelegation.validators_to_remove.is_empty() {
            redelegated_bonds.remove_all(storage, &epoch)?;
        } else {
            // Then update the redelegated bonds at this epoch
            let rbonds = redelegated_bonds.at(&epoch);
            update_redelegated_bonds(storage, &rbonds, &modified_redelegation)?;
        }
    }

    if !is_redelegation {
        // `val updatedRedelegatedUnbonded` with updates applied below
        // Delegator's redelegated unbonds to this validator.
        let delegator_redelegated_unbonded =
            delegator_redelegated_unbonds_handle(source).at(validator);

        // Quint `def updateRedelegatedUnbonded` with `val
        // updatedRedelegatedUnbonded` together with last statement
        // in `updatedDelegator.with("redelegatedUnbonded", ...` updated
        // directly in storage
        for (start, unbonds) in &new_redelegated_unbonds {
            let this_redelegated_unbonded = delegator_redelegated_unbonded
                .at(start)
                .at(&withdrawable_epoch);

            // Update the delegator's redelegated unbonds with the change
            for (src_validator, redelegated_unbonds) in unbonds {
                let redelegated_unbonded =
                    this_redelegated_unbonded.at(src_validator);
                for (&redelegation_epoch, &change) in redelegated_unbonds {
                    redelegated_unbonded.update(
                        storage,
                        redelegation_epoch,
                        |current| current.unwrap_or_default() + change,
                    )?;
                }
            }
        }
    }
    // all `val updatedDelegator` changes are applied at this point

    // `val updatedTotalBonded` and `val updatedTotalUnbonded` with updates
    // Update the validator's total bonded and unbonded amounts
    let total_bonded = total_bonded_handle(validator).get_data_handler();
    let total_unbonded = total_unbonded_handle(validator).at(&pipeline_epoch);
    for (&start_epoch, &amount) in &new_unbonds_map {
        total_bonded.update(storage, start_epoch, |current| {
            current.unwrap_or_default() - amount
        })?;
        total_unbonded.update(storage, start_epoch, |current| {
            current.unwrap_or_default() + amount
        })?;
    }

    let total_redelegated_bonded =
        validator_total_redelegated_bonded_handle(validator);
    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(validator);
    for (redelegation_start_epoch, unbonds) in &new_redelegated_unbonds {
        for (src_validator, changes) in unbonds {
            for (bond_start_epoch, change) in changes {
                // total redelegated bonded
                let bonded_sub_map = total_redelegated_bonded
                    .at(redelegation_start_epoch)
                    .at(src_validator);
                bonded_sub_map.update(
                    storage,
                    *bond_start_epoch,
                    |current| current.unwrap_or_default() - *change,
                )?;

                // total redelegated unbonded
                let unbonded_sub_map = total_redelegated_unbonded
                    .at(&pipeline_epoch)
                    .at(redelegation_start_epoch)
                    .at(src_validator);
                unbonded_sub_map.update(
                    storage,
                    *bond_start_epoch,
                    |current| current.unwrap_or_default() + *change,
                )?;
            }
        }
    }

    let slashes = find_validator_slashes(storage, validator)?;
    // `val resultSlashing`
    let result_slashing = compute_amount_after_slashing_unbond(
        storage,
        &params,
        &new_unbonds_map,
        &new_redelegated_unbonds,
        slashes,
    )?;
    #[cfg(debug_assertions)]
    let redel_bonds_post = redelegated_bonds.collect_map(storage)?;
    debug_assert!(
        result_slashing.sum <= amount,
        "Amount after slashing ({}) must be <= requested amount to unbond \
         ({}).",
        result_slashing.sum.to_string_native(),
        amount.to_string_native(),
    );

    let change_after_slashing = -result_slashing.sum.change();
    // Update the validator set at the pipeline offset. Since unbonding from a
    // jailed validator who is no longer frozen is allowed, only update the
    // validator set if the validator is not jailed
    let is_jailed_or_inactive_at_pipeline = matches!(
        validator_state_handle(validator).get(
            storage,
            pipeline_epoch,
            &params
        )?,
        Some(ValidatorState::Jailed) | Some(ValidatorState::Inactive)
    );
    if !is_jailed_or_inactive_at_pipeline {
        update_validator_set(
            storage,
            &params,
            validator,
            change_after_slashing,
            current_epoch,
            None,
        )?;
    }

    // Update the validator and total deltas at the pipeline offset
    update_validator_deltas(
        storage,
        &params,
        validator,
        change_after_slashing,
        current_epoch,
        None,
    )?;
    update_total_deltas(
        storage,
        &params,
        change_after_slashing,
        current_epoch,
        None,
    )?;

    if tracing::level_enabled!(tracing::Level::DEBUG) {
        let bonds = find_bonds(storage, source, validator)?;
        tracing::debug!("\nBonds after decrementing: {bonds:#?}");
    }

    // Invariant: in the affected epochs, the delta of bonds must be >= delta of
    // redelegated bonds deltas sum
    #[cfg(debug_assertions)]
    {
        let mut epochs = bonds_to_unbond.epochs.clone();
        if let Some((epoch, _)) = bonds_to_unbond.new_entry {
            epochs.insert(epoch);
        }
        for epoch in epochs {
            let cur_bond = bonds_handle
                .get_delta_val(storage, epoch)?
                .unwrap_or_default();
            let redelegated_deltas = redelegated_bonds
                .at(&epoch)
                // Sum of redelegations from any src validator
                .collect_map(storage)?
                .into_values()
                .map(|redeleg| redeleg.into_values().sum())
                .sum();
            debug_assert!(
                cur_bond >= redelegated_deltas,
                "After unbonding, in epoch {epoch} the bond amount {} must be \
                 >= redelegated deltas at pipeline {}.\n\nredelegated_bonds \
                 pre: {redel_bonds_pre:#?}\nredelegated_bonds post: \
                 {redel_bonds_post:#?},\nmodified_redelegation: \
                 {modified_redelegation:#?},\nbonds_to_unbond: \
                 {bonds_to_unbond:#?}",
                cur_bond.to_string_native(),
                redelegated_deltas.to_string_native()
            );
        }
    }

    // Tally rewards (only call if this is not the first epoch)
    if current_epoch > Epoch::default() {
        let mut rewards = token::Amount::zero();

        let last_claim_epoch =
            get_last_reward_claim_epoch(storage, source, validator)?
                .unwrap_or_default();
        let rewards_products = validator_rewards_products_handle(validator);

        for (start_epoch, slashed_amount) in &result_slashing.epoch_map {
            // Stop collecting rewards at the moment the unbond is initiated
            // (right now)
            for ep in
                Epoch::iter_bounds_inclusive(*start_epoch, current_epoch.prev())
            {
                // Consider the last epoch when rewards were claimed
                if ep < last_claim_epoch {
                    continue;
                }
                let rp =
                    rewards_products.get(storage, &ep)?.unwrap_or_default();
                rewards += rp * (*slashed_amount);
            }
        }

        // Update the rewards from the current unbonds first
        add_rewards_to_counter(storage, source, validator, rewards)?;
    }

    Ok(result_slashing)
}

#[derive(Debug, Default, Eq, PartialEq)]
struct FoldRedelegatedBondsResult {
    total_redelegated: token::Amount,
    total_after_slashing: token::Amount,
}

/// Iterates over a `redelegated_unbonds` and computes the both the sum of all
/// redelegated tokens and how much is left after applying all relevant slashes.
// `def foldAndSlashRedelegatedBondsMap`
fn fold_and_slash_redelegated_bonds<S>(
    storage: &S,
    params: &OwnedPosParams,
    redelegated_unbonds: &EagerRedelegatedBondsMap,
    start_epoch: Epoch,
    list_slashes: &[Slash],
    slash_epoch_filter: impl Fn(Epoch) -> bool,
) -> FoldRedelegatedBondsResult
where
    S: StorageRead,
{
    let mut result = FoldRedelegatedBondsResult::default();
    for (src_validator, bonds_map) in redelegated_unbonds {
        for (bond_start, &change) in bonds_map {
            // Merge the two lists of slashes
            let mut merged: Vec<Slash> =
            // Look-up slashes for this validator ...
                validator_slashes_handle(src_validator)
                    .iter(storage)
                    .unwrap()
                    .map(Result::unwrap)
                    .filter(|slash| {
                        params.in_redelegation_slashing_window(
                            slash.epoch,
                            params.redelegation_start_epoch_from_end(
                                start_epoch,
                            ),
                            start_epoch,
                        ) && *bond_start <= slash.epoch
                            && slash_epoch_filter(slash.epoch)
                    })
                    // ... and add `list_slashes`
                    .chain(list_slashes.iter().cloned())
                    .collect();

            // Sort slashes by epoch
            merged.sort_by(|s1, s2| s1.epoch.partial_cmp(&s2.epoch).unwrap());

            result.total_redelegated += change;
            result.total_after_slashing +=
                apply_list_slashes(params, &merged, change);
        }
    }
    result
}

/// Computes how much remains from an amount of tokens after applying a list of
/// slashes.
///
/// - `slashes` - a list of slashes ordered by misbehaving epoch.
/// - `amount` - the amount of slashable tokens.
// `def applyListSlashes`
fn apply_list_slashes(
    params: &OwnedPosParams,
    slashes: &[Slash],
    amount: token::Amount,
) -> token::Amount {
    let mut final_amount = amount;
    let mut computed_slashes = BTreeMap::<Epoch, token::Amount>::new();
    for slash in slashes {
        let slashed_amount =
            compute_slashable_amount(params, slash, amount, &computed_slashes);
        final_amount =
            final_amount.checked_sub(slashed_amount).unwrap_or_default();
        computed_slashes.insert(slash.epoch, slashed_amount);
    }
    final_amount
}

/// Computes how much is left from a bond or unbond after applying a slash given
/// that a set of slashes may have been previously applied.
// `def computeSlashableAmount`
fn compute_slashable_amount(
    params: &OwnedPosParams,
    slash: &Slash,
    amount: token::Amount,
    computed_slashes: &BTreeMap<Epoch, token::Amount>,
) -> token::Amount {
    let updated_amount = computed_slashes
        .iter()
        .filter(|(&epoch, _)| {
            // Keep slashes that have been applied and processed before the
            // current slash occurred. We use `<=` because slashes processed at
            // `slash.epoch` (at the start of the epoch) are also processed
            // before this slash occurred.
            epoch + params.slash_processing_epoch_offset() <= slash.epoch
        })
        .fold(amount, |acc, (_, &amnt)| {
            acc.checked_sub(amnt).unwrap_or_default()
        });
    updated_amount.mul_ceil(slash.rate)
}

/// Epochs for full and partial unbonds.
#[derive(Debug, Default)]
struct BondsForRemovalRes {
    /// Full unbond epochs
    pub epochs: BTreeSet<Epoch>,
    /// Partial unbond epoch associated with the new bond amount
    pub new_entry: Option<(Epoch, token::Amount)>,
}

/// In decreasing epoch order, decrement the non-zero bond amount entries until
/// the full `amount` has been removed. Returns a `BondsForRemovalRes` object
/// that contains the epochs for which the full bond amount is removed and
/// additionally information for the one epoch whose bond amount is partially
/// removed, if any.
fn find_bonds_to_remove<S>(
    storage: &S,
    bonds_handle: &LazyMap<Epoch, token::Amount>,
    amount: token::Amount,
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
        if remaining.is_zero() {
            break;
        }
    }
    Ok(bonds_for_removal)
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ModifiedRedelegation {
    epoch: Option<Epoch>,
    validators_to_remove: BTreeSet<Address>,
    validator_to_modify: Option<Address>,
    epochs_to_remove: BTreeSet<Epoch>,
    epoch_to_modify: Option<Epoch>,
    new_amount: Option<token::Amount>,
}

/// Used in `fn unbond_tokens` to compute the modified state of a redelegation
/// if redelegated tokens are being unbonded.
fn compute_modified_redelegation<S>(
    storage: &S,
    redelegated_bonds: &RedelegatedTokens,
    start_epoch: Epoch,
    amount_to_unbond: token::Amount,
) -> storage_api::Result<ModifiedRedelegation>
where
    S: StorageRead,
{
    let mut modified_redelegation = ModifiedRedelegation::default();

    let mut src_validators = BTreeSet::<Address>::new();
    let mut total_redelegated = token::Amount::zero();
    for rb in redelegated_bonds.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: src_validator,
                nested_sub_key: _,
            },
            amount,
        ) = rb?;
        total_redelegated += amount;
        src_validators.insert(src_validator);
    }

    modified_redelegation.epoch = Some(start_epoch);

    // If the total amount of redelegated bonds is less than the target amount,
    // then all redelegated bonds must be unbonded.
    if total_redelegated <= amount_to_unbond {
        return Ok(modified_redelegation);
    }

    let mut remaining = amount_to_unbond;
    for src_validator in src_validators.into_iter() {
        if remaining.is_zero() {
            break;
        }
        let rbonds = redelegated_bonds.at(&src_validator);
        let total_src_val_amount = rbonds
            .iter(storage)?
            .map(|res| {
                let (_, amount) = res?;
                Ok(amount)
            })
            .sum::<storage_api::Result<token::Amount>>()?;

        // TODO: move this into the `if total_redelegated <= remaining` branch
        // below, then we don't have to remove it in `fn
        // update_redelegated_bonds` when `validator_to_modify` is Some (and
        // avoid `modified_redelegation.validators_to_remove.clone()`).
        // It affects assumption 2. in `fn compute_new_redelegated_unbonds`, but
        // that looks trivial to change.
        // NOTE: not sure if this TODO is still relevant...
        modified_redelegation
            .validators_to_remove
            .insert(src_validator.clone());
        if total_src_val_amount <= remaining {
            remaining -= total_src_val_amount;
        } else {
            let bonds_to_remove =
                find_bonds_to_remove(storage, &rbonds, remaining)?;

            remaining = token::Amount::zero();

            // NOTE: When there are multiple `src_validators` from which we're
            // unbonding, `validator_to_modify` cannot get overridden, because
            // only one of them can be a partial unbond (`new_entry`
            // is partial unbond)
            if let Some((bond_epoch, new_bond_amount)) =
                bonds_to_remove.new_entry
            {
                modified_redelegation.validator_to_modify = Some(src_validator);
                modified_redelegation.epochs_to_remove = {
                    let mut epochs = bonds_to_remove.epochs;
                    // TODO: remove this insertion then we don't have to remove
                    // it again in `fn update_redelegated_bonds`
                    // when `epoch_to_modify` is Some (and avoid
                    // `modified_redelegation.epochs_to_remove.clone`)
                    // It affects assumption 3. in `fn
                    // compute_new_redelegated_unbonds`, but that also looks
                    // trivial to change.
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
    redelegated_bonds: &RedelegatedTokens,
    modified_redelegation: &ModifiedRedelegation,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    if let Some(val_to_modify) = &modified_redelegation.validator_to_modify {
        let mut updated_vals_to_remove =
            modified_redelegation.validators_to_remove.clone();
        updated_vals_to_remove.remove(val_to_modify);

        // Remove the updated_vals_to_remove keys from the
        // redelegated_bonds map
        for val in &updated_vals_to_remove {
            redelegated_bonds.remove_all(storage, val)?;
        }

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
        } else {
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

/// Temp helper type to match quint model.
/// Result of `compute_new_redelegated_unbonds` that contains a map of
/// redelegated unbonds.
/// The map keys from outside in are:
///
/// - redelegation end epoch where redeleg stops contributing to src validator
/// - src validator address
/// - src bond start epoch where it started contributing to src validator
type EagerRedelegatedUnbonds = BTreeMap<Epoch, EagerRedelegatedBondsMap>;

/// Computes a map of redelegated unbonds from a set of redelegated bonds.
///
/// - `redelegated_bonds` - a map of redelegated bonds from epoch to
///   `RedelegatedTokens`.
/// - `epochs_to_remove` - a set of epochs that indicate the set of epochs
///   unbonded.
/// - `modified` record that represents a redelegated bond that it is only
///   partially unbonded.
///
/// The function assumes that:
///
/// 1. `modified.epoch` is not in the `epochs_to_remove` set.
/// 2. `modified.validator_to_modify` is in `modified.vals_to_remove`.
/// 3. `modified.epoch_to_modify` is in in `modified.epochs_to_remove`.
// `def computeNewRedelegatedUnbonds` from Quint
fn compute_new_redelegated_unbonds<S>(
    storage: &S,
    redelegated_bonds: &RedelegatedBondsOrUnbonds,
    epochs_to_remove: &BTreeSet<Epoch>,
    modified: &ModifiedRedelegation,
) -> storage_api::Result<EagerRedelegatedUnbonds>
where
    S: StorageRead + StorageWrite,
{
    let unbonded_epochs = if let Some(epoch) = modified.epoch {
        debug_assert!(
            !epochs_to_remove.contains(&epoch),
            "1. assumption in `fn compute_new_redelegated_unbonds` doesn't \
             hold"
        );
        let mut epochs = epochs_to_remove.clone();
        epochs.insert(epoch);
        epochs
            .iter()
            .cloned()
            .filter(|e| redelegated_bonds.contains(storage, e).unwrap())
            .collect::<BTreeSet<Epoch>>()
    } else {
        epochs_to_remove
            .iter()
            .cloned()
            .filter(|e| redelegated_bonds.contains(storage, e).unwrap())
            .collect::<BTreeSet<Epoch>>()
    };
    debug_assert!(
        modified
            .validator_to_modify
            .as_ref()
            .map(|validator| modified.validators_to_remove.contains(validator))
            .unwrap_or(true),
        "2. assumption in `fn compute_new_redelegated_unbonds` doesn't hold"
    );
    debug_assert!(
        modified
            .epoch_to_modify
            .as_ref()
            .map(|epoch| modified.epochs_to_remove.contains(epoch))
            .unwrap_or(true),
        "3. assumption in `fn compute_new_redelegated_unbonds` doesn't hold"
    );

    // quint `newRedelegatedUnbonds` returned from
    // `computeNewRedelegatedUnbonds`
    let new_redelegated_unbonds: EagerRedelegatedUnbonds = unbonded_epochs
        .into_iter()
        .map(|start| {
            let mut rbonds = EagerRedelegatedBondsMap::default();
            if modified
                .epoch
                .map(|redelegation_epoch| start != redelegation_epoch)
                .unwrap_or(true)
                || modified.validators_to_remove.is_empty()
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
                for src_validator in &modified.validators_to_remove {
                    if modified
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
                        for bond_start in &modified.epochs_to_remove {
                            let cur_redel_bond_amount = redelegated_bonds
                                .at(&start)
                                .at(src_validator)
                                .get(storage, bond_start)
                                .unwrap()
                                .unwrap_or_default();
                            let raw_bonds = rbonds
                                .entry(src_validator.clone())
                                .or_default();
                            if modified
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
                                        - modified
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

/// Compute a token amount after slashing, given the initial amount and a set of
/// slashes. It is assumed that the input `slashes` are those committed while
/// the `amount` was contributing to voting power.
fn get_slashed_amount(
    params: &PosParams,
    amount: token::Amount,
    slashes: &BTreeMap<Epoch, Dec>,
) -> storage_api::Result<token::Amount> {
    let mut updated_amount = amount;
    let mut computed_amounts = Vec::<SlashedAmount>::new();

    for (&infraction_epoch, &slash_rate) in slashes {
        let mut computed_to_remove = BTreeSet::<Reverse<usize>>::new();
        for (ix, slashed_amount) in computed_amounts.iter().enumerate() {
            // Update amount with slashes that happened more than unbonding_len
            // epochs before this current slash
            if slashed_amount.epoch + params.slash_processing_epoch_offset()
                <= infraction_epoch
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
            amount: updated_amount.mul_ceil(slash_rate),
            epoch: infraction_epoch,
        });
    }

    let total_computed_amounts = computed_amounts
        .into_iter()
        .map(|slashed| slashed.amount)
        .sum();

    let final_amount = updated_amount
        .checked_sub(total_computed_amounts)
        .unwrap_or_default();

    Ok(final_amount)
}

// `def computeAmountAfterSlashingUnbond`
fn compute_amount_after_slashing_unbond<S>(
    storage: &S,
    params: &OwnedPosParams,
    unbonds: &BTreeMap<Epoch, token::Amount>,
    redelegated_unbonds: &EagerRedelegatedUnbonds,
    slashes: Vec<Slash>,
) -> storage_api::Result<ResultSlashing>
where
    S: StorageRead,
{
    let mut result_slashing = ResultSlashing::default();
    for (&start_epoch, amount) in unbonds {
        // `val listSlashes`
        let list_slashes: Vec<Slash> = slashes
            .iter()
            .filter(|slash| slash.epoch >= start_epoch)
            .cloned()
            .collect();
        // `val resultFold`
        let result_fold = if let Some(redelegated_unbonds) =
            redelegated_unbonds.get(&start_epoch)
        {
            fold_and_slash_redelegated_bonds(
                storage,
                params,
                redelegated_unbonds,
                start_epoch,
                &list_slashes,
                |_| true,
            )
        } else {
            FoldRedelegatedBondsResult::default()
        };
        // `val totalNoRedelegated`
        let total_not_redelegated = amount
            .checked_sub(result_fold.total_redelegated)
            .unwrap_or_default();
        // `val afterNoRedelegated`
        let after_not_redelegated =
            apply_list_slashes(params, &list_slashes, total_not_redelegated);
        // `val amountAfterSlashing`
        let amount_after_slashing =
            after_not_redelegated + result_fold.total_after_slashing;
        // Accumulation step
        result_slashing.sum += amount_after_slashing;
        result_slashing
            .epoch_map
            .insert(start_epoch, amount_after_slashing);
    }
    Ok(result_slashing)
}

/// Compute from a set of unbonds (both redelegated and not) how much is left
/// after applying all relevant slashes.
// `def computeAmountAfterSlashingWithdraw`
fn compute_amount_after_slashing_withdraw<S>(
    storage: &S,
    params: &OwnedPosParams,
    unbonds_and_redelegated_unbonds: &BTreeMap<
        (Epoch, Epoch),
        (token::Amount, EagerRedelegatedBondsMap),
    >,
    slashes: Vec<Slash>,
) -> storage_api::Result<ResultSlashing>
where
    S: StorageRead,
{
    let mut result_slashing = ResultSlashing::default();

    for ((start_epoch, withdraw_epoch), (amount, redelegated_unbonds)) in
        unbonds_and_redelegated_unbonds.iter()
    {
        // TODO: check if slashes in the same epoch can be
        // folded into one effective slash
        let end_epoch = *withdraw_epoch
            - params.unbonding_len
            - params.cubic_slashing_window_length;
        // Find slashes that apply to `start_epoch..end_epoch`
        let list_slashes = slashes
            .iter()
            .filter(|slash| {
                // Started before the slash occurred
                start_epoch <= &slash.epoch
                    // Ends after the slash
                    && end_epoch > slash.epoch
            })
            .cloned()
            .collect::<Vec<_>>();

        // Find the sum and the sum after slashing of the redelegated unbonds
        let result_fold = fold_and_slash_redelegated_bonds(
            storage,
            params,
            redelegated_unbonds,
            *start_epoch,
            &list_slashes,
            |_| true,
        );

        // Unbond amount that didn't come from a redelegation
        let total_not_redelegated = *amount - result_fold.total_redelegated;
        // Find how much remains after slashing non-redelegated amount
        let after_not_redelegated =
            apply_list_slashes(params, &list_slashes, total_not_redelegated);

        // Add back the unbond and redelegated unbond amount after slashing
        let amount_after_slashing =
            after_not_redelegated + result_fold.total_after_slashing;

        result_slashing.sum += amount_after_slashing;
        result_slashing
            .epoch_map
            .insert(*start_epoch, amount_after_slashing);
    }

    Ok(result_slashing)
}

/// Arguments to [`become_validator`].
pub struct BecomeValidator<'a> {
    /// Proof-of-stake parameters.
    pub params: &'a PosParams,
    /// The validator's address.
    pub address: &'a Address,
    /// The validator's consensus key, used by Tendermint.
    pub consensus_key: &'a common::PublicKey,
    /// The validator's protocol key.
    pub protocol_key: &'a common::PublicKey,
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
    /// Validator metadata
    pub metadata: ValidatorMetaData,
    /// Optional offset to use instead of pipeline offset
    pub offset_opt: Option<u64>,
}

/// Initialize data for a new validator.
pub fn become_validator<S>(
    storage: &mut S,
    args: BecomeValidator<'_>,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let BecomeValidator {
        params,
        address,
        consensus_key,
        protocol_key,
        eth_cold_key,
        eth_hot_key,
        current_epoch,
        commission_rate,
        max_commission_rate_change,
        metadata,
        offset_opt,
    } = args;
    let offset = offset_opt.unwrap_or(params.pipeline_len);

    if !address.is_established() {
        return Err(storage_api::Error::new_const(
            "The given address {address} is not established. Only an \
             established address can become a validator.",
        ));
    }

    if is_validator(storage, address)? {
        return Err(storage_api::Error::new_const(
            "The given address is already a validator",
        ));
    }

    // If the address is not yet a validator, it cannot have self-bonds, but it
    // may have delegations.
    if has_bonds(storage, address)? {
        return Err(storage_api::Error::new_const(
            "The given address has delegations and therefore cannot become a \
             validator. Unbond first.",
        ));
    }

    // This will fail if the key is already being used
    try_insert_consensus_key(storage, consensus_key)?;

    let pipeline_epoch = current_epoch + offset;
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
    write_validator_metadata(storage, address, &metadata)?;

    // Epoched validator data
    validator_consensus_key_handle(address).set(
        storage,
        consensus_key.clone(),
        current_epoch,
        offset,
    )?;
    validator_protocol_key_handle(address).set(
        storage,
        protocol_key.clone(),
        current_epoch,
        offset,
    )?;
    validator_eth_hot_key_handle(address).set(
        storage,
        eth_hot_key.clone(),
        current_epoch,
        offset,
    )?;
    validator_eth_cold_key_handle(address).set(
        storage,
        eth_cold_key.clone(),
        current_epoch,
        offset,
    )?;
    validator_commission_rate_handle(address).set(
        storage,
        commission_rate,
        current_epoch,
        offset,
    )?;
    validator_deltas_handle(address).set(
        storage,
        token::Change::zero(),
        current_epoch,
        offset,
    )?;

    // The validator's stake at initialization is 0, so its state is immediately
    // below-threshold
    validator_state_handle(address).set(
        storage,
        ValidatorState::BelowThreshold,
        current_epoch,
        offset,
    )?;

    insert_validator_into_validator_set(
        storage,
        params,
        address,
        token::Amount::zero(),
        current_epoch,
        offset,
    )?;

    Ok(())
}

/// Consensus key change for a validator
pub fn change_consensus_key<S>(
    storage: &mut S,
    validator: &Address,
    consensus_key: &common::PublicKey,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    tracing::debug!("Changing consensus key for validator {}", validator);

    // Require that the new consensus key is an Ed25519 key
    match consensus_key {
        common::PublicKey::Ed25519(_) => {}
        common::PublicKey::Secp256k1(_) => {
            return Err(ConsensusKeyChangeError::MustBeEd25519.into());
        }
    }

    // Check for uniqueness of the consensus key
    try_insert_consensus_key(storage, consensus_key)?;

    // Set the new consensus key at the pipeline epoch
    let params = read_pos_params(storage)?;
    validator_consensus_key_handle(validator).set(
        storage,
        consensus_key.clone(),
        current_epoch,
        params.pipeline_len,
    )?;

    // Write validator's new raw hash
    write_validator_address_raw_hash(storage, validator, consensus_key)?;

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

    let unbond_handle: Unbonds = unbond_handle(source, validator);
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

    let mut unbonds_and_redelegated_unbonds: BTreeMap<
        (Epoch, Epoch),
        (token::Amount, EagerRedelegatedBondsMap),
    > = BTreeMap::new();

    for unbond in unbond_handle.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: start_epoch,
                nested_sub_key: SubKey::Data(withdraw_epoch),
            },
            amount,
        ) = unbond?;

        // Logging
        tracing::debug!(
            "Unbond delta ({start_epoch}..{withdraw_epoch}), amount {}",
            amount.to_string_native()
        );
        // Consider only unbonds that are eligible to be withdrawn
        if withdraw_epoch > current_epoch {
            tracing::debug!(
                "Not yet withdrawable until epoch {withdraw_epoch}"
            );
            continue;
        }

        let mut eager_redelegated_unbonds = EagerRedelegatedBondsMap::default();
        let matching_redelegated_unbonds =
            redelegated_unbonds.at(&start_epoch).at(&withdraw_epoch);
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

        unbonds_and_redelegated_unbonds.insert(
            (start_epoch, withdraw_epoch),
            (amount, eager_redelegated_unbonds),
        );
    }

    let slashes = find_validator_slashes(storage, validator)?;

    // `val resultSlashing`
    let result_slashing = compute_amount_after_slashing_withdraw(
        storage,
        &params,
        &unbonds_and_redelegated_unbonds,
        slashes,
    )?;

    let withdrawable_amount = result_slashing.sum;
    tracing::debug!(
        "Withdrawing total {}",
        withdrawable_amount.to_string_native()
    );

    // `updateDelegator` with `unbonded` and `redelegeatedUnbonded`
    for ((start_epoch, withdraw_epoch), _unbond_and_redelegations) in
        unbonds_and_redelegated_unbonds
    {
        tracing::debug!("Remove ({start_epoch}..{withdraw_epoch}) from unbond");
        unbond_handle
            .at(&start_epoch)
            .remove(storage, &withdraw_epoch)?;
        redelegated_unbonds
            .at(&start_epoch)
            .remove_all(storage, &withdraw_epoch)?;

        if unbond_handle.at(&start_epoch).is_empty(storage)? {
            unbond_handle.remove_all(storage, &start_epoch)?;
        }
        if redelegated_unbonds.at(&start_epoch).is_empty(storage)? {
            redelegated_unbonds.remove_all(storage, &start_epoch)?;
        }
    }

    // Transfer the withdrawable tokens from the PoS address back to the source
    let staking_token = staking_token_address(storage);
    token::transfer(
        storage,
        &staking_token,
        &ADDRESS,
        source,
        withdrawable_amount,
    )?;

    // TODO: Transfer the slashed tokens from the PoS address to the Slash Pool
    // address
    // token::transfer(
    //     storage,
    //     &staking_token,
    //     &ADDRESS,
    //     &SLASH_POOL_ADDRESS,
    //     total_slashed,
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
    if new_rate.is_negative() {
        return Err(CommissionRateChangeError::NegativeRate(
            new_rate,
            validator.clone(),
        )
        .into());
    }

    if new_rate > Dec::one() {
        return Err(CommissionRateChangeError::LargerThanOne(
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
        .get(storage, pipeline_epoch.prev(), &params)?
        .expect("Could not find a rate in given epoch");

    let change_from_prev = new_rate.abs_diff(&rate_before_pipeline);
    if change_from_prev > max_change.unwrap() {
        return Err(CommissionRateChangeError::RateChangeTooLarge(
            change_from_prev,
            validator.clone(),
        )
        .into());
    }

    commission_handle.set(storage, new_rate, current_epoch, params.pipeline_len)
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

/// Get the unique set of consensus keys in storage
pub fn get_consensus_key_set<S>(
    storage: &S,
) -> storage_api::Result<BTreeSet<common::PublicKey>>
where
    S: StorageRead,
{
    let key = consensus_keys_key();
    let lazy_set = LazySet::<common::PublicKey>::open(key);
    Ok(lazy_set.iter(storage)?.map(Result::unwrap).collect())
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
/// Returns the bond amount after slashing. For future epochs the value is
/// subject to change.
pub fn bond_amount<S>(
    storage: &S,
    bond_id: &BondId,
    epoch: Epoch,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    let params = read_pos_params(storage)?;
    // Outer key is the start epoch used to calculate slashes. The inner
    // keys are discarded after applying slashes.
    let mut amounts: BTreeMap<Epoch, token::Amount> = BTreeMap::default();

    // Bonds
    let bonds =
        bond_handle(&bond_id.source, &bond_id.validator).get_data_handler();
    for next in bonds.iter(storage)? {
        let (start, delta) = next?;
        if start <= epoch {
            let amount = amounts.entry(start).or_default();
            *amount += delta;
        }
    }

    // Add unbonds that are still contributing to stake
    let unbonds = unbond_handle(&bond_id.source, &bond_id.validator);
    for next in unbonds.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: start,
                nested_sub_key: SubKey::Data(withdrawable_epoch),
            },
            delta,
        ) = next?;
        // This is the first epoch in which the unbond stops contributing to
        // voting power
        let end = withdrawable_epoch - params.withdrawable_epoch_offset()
            + params.pipeline_len;

        if start <= epoch && end > epoch {
            let amount = amounts.entry(start).or_default();
            *amount += delta;
        }
    }

    if bond_id.validator != bond_id.source {
        // Add outgoing redelegations that are still contributing to the source
        // validator's stake
        let redelegated_bonds =
            delegator_redelegated_bonds_handle(&bond_id.source);
        for res in redelegated_bonds.iter(storage)? {
            let (
                NestedSubKey::Data {
                    key: _dest_validator,
                    nested_sub_key:
                        NestedSubKey::Data {
                            key: end,
                            nested_sub_key:
                                NestedSubKey::Data {
                                    key: src_validator,
                                    nested_sub_key: SubKey::Data(start),
                                },
                        },
                },
                delta,
            ) = res?;
            if src_validator == bond_id.validator
                && start <= epoch
                && end > epoch
            {
                let amount = amounts.entry(start).or_default();
                *amount += delta;
            }
        }

        // Add outgoing redelegation unbonds that are still contributing to
        // the source validator's stake
        let redelegated_unbonds =
            delegator_redelegated_unbonds_handle(&bond_id.source);
        for res in redelegated_unbonds.iter(storage)? {
            let (
                NestedSubKey::Data {
                    key: _dest_validator,
                    nested_sub_key:
                        NestedSubKey::Data {
                            key: redelegation_epoch,
                            nested_sub_key:
                                NestedSubKey::Data {
                                    key: _withdraw_epoch,
                                    nested_sub_key:
                                        NestedSubKey::Data {
                                            key: src_validator,
                                            nested_sub_key: SubKey::Data(start),
                                        },
                                },
                        },
                },
                delta,
            ) = res?;
            if src_validator == bond_id.validator
                // If the unbonded bond was redelegated after this epoch ...
                && redelegation_epoch > epoch
                // ... the start was before or at this epoch
                && start <= epoch
            {
                let amount = amounts.entry(start).or_default();
                *amount += delta;
            }
        }
    }

    if !amounts.is_empty() {
        let slashes = find_validator_slashes(storage, &bond_id.validator)?;

        // Apply slashes
        for (&start, amount) in amounts.iter_mut() {
            let list_slashes = slashes
                .iter()
                .filter(|slash| {
                    let processing_epoch =
                        slash.epoch + params.slash_processing_epoch_offset();
                    // Only use slashes that were processed before or at the
                    // epoch associated with the bond amount. This assumes
                    // that slashes are applied before inflation.
                    processing_epoch <= epoch && start <= slash.epoch
                })
                .cloned()
                .collect::<Vec<_>>();

            *amount = apply_list_slashes(&params, &list_slashes, *amount);
        }
    }

    Ok(amounts.values().cloned().sum())
}

/// Get bond amounts within the `claim_start..=claim_end` epoch range for
/// claiming rewards for a given bond ID. Returns a map of bond amounts
/// associated with every epoch within the given epoch range (accumulative) in
/// which an amount contributed to the validator's stake.
/// This function will only consider slashes that were processed before or at
/// the epoch in which we're calculating the bond amount to correspond to the
/// validator stake that was used to calculate reward products (slashes do *not*
/// retrospectively affect the rewards calculated before slash processing).
pub fn bond_amounts_for_rewards<S>(
    storage: &S,
    bond_id: &BondId,
    claim_start: Epoch,
    claim_end: Epoch,
) -> storage_api::Result<BTreeMap<Epoch, token::Amount>>
where
    S: StorageRead,
{
    let params = read_pos_params(storage)?;
    // Outer key is every epoch in which the a bond amount contributed to stake
    // and the inner key is the start epoch used to calculate slashes. The inner
    // keys are discarded after applying slashes.
    let mut amounts: BTreeMap<Epoch, BTreeMap<Epoch, token::Amount>> =
        BTreeMap::default();

    // Only need to do bonds since rewwards are accumulated during
    // `unbond_tokens`
    let bonds =
        bond_handle(&bond_id.source, &bond_id.validator).get_data_handler();
    for next in bonds.iter(storage)? {
        let (start, delta) = next?;

        for ep in Epoch::iter_bounds_inclusive(claim_start, claim_end) {
            // A bond that wasn't unbonded is added to all epochs up to
            // `claim_end`
            if start <= ep {
                let amount =
                    amounts.entry(ep).or_default().entry(start).or_default();
                *amount += delta;
            }
        }
    }

    if !amounts.is_empty() {
        let slashes = find_validator_slashes(storage, &bond_id.validator)?;
        let redelegated_bonded =
            delegator_redelegated_bonds_handle(&bond_id.source)
                .at(&bond_id.validator);

        // Apply slashes
        for (&ep, amounts) in amounts.iter_mut() {
            for (&start, amount) in amounts.iter_mut() {
                let list_slashes = slashes
                    .iter()
                    .filter(|slash| {
                        let processing_epoch = slash.epoch
                            + params.slash_processing_epoch_offset();
                        // Only use slashes that were processed before or at the
                        // epoch associated with the bond amount. This assumes
                        // that slashes are applied before inflation.
                        processing_epoch <= ep && start <= slash.epoch
                    })
                    .cloned()
                    .collect::<Vec<_>>();

                let slash_epoch_filter =
                    |e: Epoch| e + params.slash_processing_epoch_offset() <= ep;

                let redelegated_bonds =
                    redelegated_bonded.at(&start).collect_map(storage)?;

                let result_fold = fold_and_slash_redelegated_bonds(
                    storage,
                    &params,
                    &redelegated_bonds,
                    start,
                    &list_slashes,
                    slash_epoch_filter,
                );

                let total_not_redelegated =
                    *amount - result_fold.total_redelegated;

                let after_not_redelegated = apply_list_slashes(
                    &params,
                    &list_slashes,
                    total_not_redelegated,
                );

                *amount =
                    after_not_redelegated + result_fold.total_after_slashing;
            }
        }
    }

    Ok(amounts
        .into_iter()
        // Flatten the inner maps to discard bond start epochs
        .map(|(ep, amounts)| (ep, amounts.values().cloned().sum()))
        .collect())
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
    let next_epoch = current_epoch.next();

    let new_consensus_validator_handle =
        consensus_validator_set_handle().at(&next_epoch);
    let prev_consensus_validator_handle =
        consensus_validator_set_handle().at(&current_epoch);

    let new_consensus_validators = new_consensus_validator_handle
        .iter(storage)?
        .map(|validator| {
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

            let new_consensus_key = validator_consensus_key_handle(&address)
                .get(storage, next_epoch, params)
                .unwrap()
                .unwrap();

            let old_consensus_key = validator_consensus_key_handle(&address)
                .get(storage, current_epoch, params)
                .unwrap();

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
                    .unwrap();
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
                    if old_consensus_key.as_ref().unwrap() == &new_consensus_key
                    {
                        tracing::debug!(
                            "skipping validator update, {address} is in \
                             consensus set but voting power hasn't changed"
                        );
                        return vec![];
                    } else {
                        return vec![
                            ValidatorSetUpdate::Consensus(ConsensusValidator {
                                consensus_key: new_consensus_key,
                                bonded_stake: new_stake,
                            }),
                            ValidatorSetUpdate::Deactivated(
                                old_consensus_key.unwrap(),
                            ),
                        ];
                    }
                }
                // If both previous and current voting powers are 0, and the
                // validator_stake_threshold is 0, skip update
                if params.validator_stake_threshold.is_zero()
                    && *prev_tm_voting_power == 0
                    && *new_tm_voting_power == 0
                {
                    tracing::info!(
                        "skipping validator update, {address} is in consensus \
                         set but without voting power"
                    );
                    return vec![];
                }
            }

            tracing::debug!(
                "{address} consensus key {}",
                new_consensus_key.tm_raw_hash()
            );

            if old_consensus_key.as_ref() == Some(&new_consensus_key)
                || old_consensus_key.is_none()
            {
                vec![ValidatorSetUpdate::Consensus(ConsensusValidator {
                    consensus_key: new_consensus_key,
                    bonded_stake: new_stake,
                })]
            } else {
                vec![
                    ValidatorSetUpdate::Consensus(ConsensusValidator {
                        consensus_key: new_consensus_key,
                        bonded_stake: new_stake,
                    }),
                    ValidatorSetUpdate::Deactivated(old_consensus_key.unwrap()),
                ]
            }
        });

    let prev_consensus_validators = prev_consensus_validator_handle
        .iter(storage)?
        .map(|validator| {
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
                .unwrap();
                into_tm_voting_power(
                    params.tm_votes_per_token,
                    prev_validator_stake,
                )
            });

            let old_consensus_key = validator_consensus_key_handle(&address)
                .get(storage, current_epoch, params)
                .unwrap()
                .unwrap();

            // If the validator is still in the Consensus set, we accounted for
            // it in the `new_consensus_validators` iterator above
            if matches!(new_state, Some(ValidatorState::Consensus)) {
                return vec![];
            } else if params.validator_stake_threshold.is_zero()
                && *prev_tm_voting_power == 0
            {
                // If the new state is not Consensus but its prev voting power
                // was 0 and the stake threshold is 0, we can also skip the
                // update
                tracing::info!(
                    "skipping validator update, {address} is in consensus set \
                     but without voting power"
                );
                return vec![];
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
            vec![ValidatorSetUpdate::Deactivated(old_consensus_key)]
        });

    Ok(new_consensus_validators
        .chain(prev_consensus_validators)
        .flatten()
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
        let deltas_sum = bond_handle(owner, &validator_address)
            .get_sum(storage, *epoch, &params)?
            .unwrap_or_default();
        delegations.insert(validator_address, deltas_sum);
    }
    Ok(delegations)
}

/// Find if the given source address has any bonds.
pub fn has_bonds<S>(storage: &S, source: &Address) -> storage_api::Result<bool>
where
    S: StorageRead,
{
    let max_epoch = Epoch(u64::MAX);
    let delegations = find_delegations(storage, source, &max_epoch)?;
    Ok(!delegations
        .values()
        .cloned()
        .sum::<token::Amount>()
        .is_zero())
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
) -> storage_api::Result<BTreeMap<Epoch, token::Amount>>
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
                    key: start_epoch,
                    nested_sub_key: SubKey::Data(withdraw_epoch),
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
                    let change: token::Amount =
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
        .filter(|(_start, amount)| *amount > token::Amount::zero())
        .map(|(start, amount)| {
            make_bond_details(
                params,
                &validator,
                amount,
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
    deltas_sum: token::Amount,
    start: Epoch,
    slashes: &[Slash],
    applied_slashes: &mut HashMap<Address, Vec<Slash>>,
) -> BondDetails {
    let prev_applied_slashes = applied_slashes
        .clone()
        .get(validator)
        .cloned()
        .unwrap_or_default();

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
        let amount_after_slashing =
            get_slashed_amount(params, deltas_sum, &slash_rates_by_epoch)
                .unwrap();
        Some(deltas_sum - amount_after_slashing)
    };

    BondDetails {
        start,
        amount: deltas_sum,
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
                    .checked_sub(
                        params.unbonding_len
                            + params.cubic_slashing_window_length,
                    )
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
        let amount_after_slashing =
            get_slashed_amount(params, amount, &slash_rates_by_epoch).unwrap();
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
    let total_consensus_stake =
        get_total_consensus_stake(storage, epoch, &params)?;

    // Get set of signing validator addresses and the combined stake of
    // these signers
    let mut signer_set: HashSet<Address> = HashSet::new();
    let mut total_signing_stake = token::Amount::zero();
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
            read_validator_stake(storage, &params, &validator_address, epoch)?;

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

    // tracing::debug!(
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

        if stake.is_zero() {
            continue;
        }

        let mut rewards_frac = Dec::zero();
        let stake_unscaled: Dec = stake.into();
        // tracing::debug!(
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

        // To be added to the rewards accumulator
        values.insert(address, rewards_frac);
    }
    for (address, value) in values.into_iter() {
        // Update the rewards accumulator
        rewards_accumulator_handle().update(storage, address, |prev| {
            prev.unwrap_or_default() + value
        })?;
    }

    Ok(())
}

#[derive(Clone, Debug)]
struct Rewards {
    product: Dec,
    commissions: token::Amount,
}

/// Update validator and delegators rewards products and mint the inflation
/// tokens into the PoS account.
/// Any left-over inflation tokens from rounding error of the sum of the
/// rewards is given to the governance address.
pub fn update_rewards_products_and_mint_inflation<S>(
    storage: &mut S,
    params: &PosParams,
    last_epoch: Epoch,
    num_blocks_in_last_epoch: u64,
    inflation: token::Amount,
    staking_token: &Address,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    // Read the rewards accumulator and calculate the new rewards products
    // for the previous epoch
    let mut reward_tokens_remaining = inflation;
    let mut new_rewards_products: HashMap<Address, Rewards> = HashMap::new();
    let mut accumulators_sum = Dec::zero();
    for acc in rewards_accumulator_handle().iter(storage)? {
        let (validator, value) = acc?;
        accumulators_sum += value;

        // Get reward token amount for this validator
        let fractional_claim = value / num_blocks_in_last_epoch;
        let reward_tokens = fractional_claim * inflation;

        // Get validator stake at the last epoch
        let stake = Dec::from(read_validator_stake(
            storage, params, &validator, last_epoch,
        )?);

        let commission_rate = validator_commission_rate_handle(&validator)
            .get(storage, last_epoch, params)?
            .expect("Should be able to find validator commission rate");

        // Calculate the reward product from the whole validator stake and take
        // out the commissions. Because we're using the whole stake to work with
        // a single product, we're also taking out commission on validator's
        // self-bonds, but it is then included in the rewards claimable by the
        // validator so they get it back.
        let product =
            (Dec::one() - commission_rate) * Dec::from(reward_tokens) / stake;

        // Tally the commission tokens earned by the validator.
        // TODO: think abt Dec rounding and if `new_product` should be used
        // instead of `reward_tokens`
        let commissions = commission_rate * reward_tokens;

        new_rewards_products.insert(
            validator,
            Rewards {
                product,
                commissions,
            },
        );

        reward_tokens_remaining -= reward_tokens;
    }
    for (
        validator,
        Rewards {
            product,
            commissions,
        },
    ) in new_rewards_products
    {
        validator_rewards_products_handle(&validator)
            .insert(storage, last_epoch, product)?;
        // The commissions belong to the validator
        add_rewards_to_counter(storage, &validator, &validator, commissions)?;
    }

    // Mint tokens to the PoS account for the last epoch's inflation
    let pos_reward_tokens = inflation - reward_tokens_remaining;
    tracing::info!(
        "Minting tokens for PoS rewards distribution into the PoS account. \
         Amount: {}. Total inflation: {}, number of blocks in the last epoch: \
         {num_blocks_in_last_epoch}, reward accumulators sum: \
         {accumulators_sum}.",
        pos_reward_tokens.to_string_native(),
        inflation.to_string_native(),
    );
    token::credit_tokens(
        storage,
        staking_token,
        &address::POS,
        pos_reward_tokens,
    )?;

    if reward_tokens_remaining > token::Amount::zero() {
        tracing::info!(
            "Minting tokens remaining from PoS rewards distribution into the \
             Governance account. Amount: {}.",
            reward_tokens_remaining.to_string_native()
        );
        token::credit_tokens(
            storage,
            staking_token,
            &address::GOV,
            reward_tokens_remaining,
        )?;
    }

    // Clear validator rewards accumulators
    storage.delete_prefix(
        // The prefix of `rewards_accumulator_handle`
        &storage::consensus_validator_rewards_accumulator_key(),
    )?;

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
    tracing::debug!(
        "Computing the cubic slash rate for infraction epoch \
         {infraction_epoch}."
    );
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
                    read_validator_stake(storage, params, &validator, epoch)?;
                // tracing::debug!("Val {} stake: {}", &validator,
                // validator_stake);

                Ok(acc + Dec::from(validator_stake))
            },
        )?;
        sum_vp_fraction += infracting_stake / consensus_stake;
    }
    let cubic_rate =
        Dec::new(9, 0).unwrap() * sum_vp_fraction * sum_vp_fraction;
    tracing::debug!("Cubic slash rate: {}", cubic_rate);
    Ok(cubic_rate)
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

    // Jail the validator and update validator sets
    jail_validator(
        storage,
        params,
        validator,
        current_epoch,
        validator_set_update_epoch,
    )?;

    // No other actions are performed here until the epoch in which the slash is
    // processed.

    Ok(())
}

/// Process enqueued slashes that were discovered earlier. This function is
/// called upon a new epoch. The final slash rate considering according to the
/// cubic slashing rate is computed. Then, each slash is recorded in storage
/// along with its computed rate, and stake is deducted from the affected
/// validators.
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
    let mut eager_validator_slashes: BTreeMap<Address, Vec<Slash>> =
        BTreeMap::new();
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

        let cur_slashes = eager_validator_slashes
            .entry(validator.clone())
            .or_default();
        cur_slashes.push(updated_slash);
        let cur_rate =
            eager_validator_slash_rates.entry(validator).or_default();
        *cur_rate = cmp::min(Dec::one(), *cur_rate + slash_rate);
    }

    // Update the epochs of enqueued slashes in storage
    enqueued_slashes_handle().update_data(storage, &params, current_epoch)?;

    // `resultSlashing`
    let mut map_validator_slash: EagerRedelegatedBondsMap = BTreeMap::new();
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
    tracing::debug!("Slashed amounts for validators: {map_validator_slash:#?}");

    // Now update the remaining parts of storage

    // Write slashes themselves into storage
    for (validator, slashes) in eager_validator_slashes {
        let validator_slashes = validator_slashes_handle(&validator);
        for slash in slashes {
            validator_slashes.push(storage, slash)?;
        }
    }

    // Update the validator stakes
    for (validator, slash_amounts) in map_validator_slash {
        let mut slash_acc = token::Amount::zero();

        // Update validator sets first because it needs to be able to read
        // validator stake before we make any changes to it
        for (&epoch, &slash_amount) in &slash_amounts {
            let state = validator_state_handle(&validator)
                .get(storage, epoch, &params)?
                .unwrap();
            if state != ValidatorState::Jailed {
                update_validator_set(
                    storage,
                    &params,
                    &validator,
                    -slash_amount.change(),
                    epoch,
                    Some(0),
                )?;
            }
        }
        // Then update validator and total deltas
        for (epoch, slash_amount) in slash_amounts {
            let slash_delta = slash_amount - slash_acc;
            slash_acc += slash_delta;

            update_validator_deltas(
                storage,
                &params,
                &validator,
                -slash_delta.change(),
                epoch,
                Some(0),
            )?;
            update_total_deltas(
                storage,
                &params,
                -slash_delta.change(),
                epoch,
                Some(0),
            )?;
        }

        // TODO: should we clear some storage here as is done in Quint??
        // Possibly make the `unbonded` LazyMaps epoched so that it is done
        // automatically?
    }

    Ok(())
}

/// Process a slash by (i) slashing the misbehaving validator; and (ii) any
/// validator to which it has redelegated some tokens and the slash misbehaving
/// epoch is within the redelegation slashing window.
///
/// `validator` - the misbehaving validator.
/// `slash_rate` - the slash rate.
/// `slashed_amounts_map` - a map from validator address to a map from epoch to
/// already processed slash amounts.
///
/// Adds any newly processed slash amount of any involved validator to
/// `slashed_amounts_map`.
// Quint `processSlash`
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
    let validator_slashes =
        slashed_amount_map.entry(validator.clone()).or_default();
    *validator_slashes = result_slash;

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
        .collect::<storage_api::Result<BTreeSet<_>>>()?;

    for dest_validator in dest_validators {
        let to_modify = slashed_amount_map
            .entry(dest_validator.clone())
            .or_default();

        tracing::debug!(
            "Slashing {} redelegation to {}",
            validator,
            &dest_validator
        );

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

/// In the context of a redelegation, the function computes how much a validator
/// (the destination validator of the redelegation) should be slashed due to the
/// misbehaving of a second validator (the source validator of the
/// redelegation). The function computes how much the validator would be
/// slashed at all epochs between the current epoch (curEpoch) + 1 and the
/// current epoch + 1 + PIPELINE_OFFSET, accounting for any tokens of the
/// redelegation already unbonded.
///
/// - `src_validator` - the source validator
/// - `outgoing_redelegations` - a map from pair of epochs to int that includes
///   all the redelegations from the source validator to the destination
///   validator.
///     - The outer key is epoch at which the bond started at the source
///       validator.
///     - The inner key is epoch at which the redelegation started (the epoch at
///       which was issued).
/// - `slashes` a list of slashes of the source validator.
/// - `dest_total_redelegated_unbonded` - a map of unbonded redelegated tokens
///   at the destination validator.
/// - `slash_rate` - the rate of the slash being processed.
/// - `dest_slashed_amounts` - a map from epoch to already processed slash
///   amounts.
///
/// Adds any newly processed slash amount to `dest_slashed_amounts`.
#[allow(clippy::too_many_arguments)]
fn slash_validator_redelegation<S>(
    storage: &S,
    params: &OwnedPosParams,
    src_validator: &Address,
    current_epoch: Epoch,
    outgoing_redelegations: &NestedMap<Epoch, LazyMap<Epoch, token::Amount>>,
    slashes: &Slashes,
    dest_total_redelegated_unbonded: &TotalRedelegatedUnbonded,
    slash_rate: Dec,
    dest_slashed_amounts: &mut BTreeMap<Epoch, token::Amount>,
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
                amount,
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
    params: &OwnedPosParams,
    amount: token::Amount,
    bond_start: Epoch,
    redel_bond_start: Epoch,
    src_validator: &Address,
    current_epoch: Epoch,
    slashes: &Slashes,
    total_redelegated_unbonded: &TotalRedelegatedUnbonded,
    slash_rate: Dec,
    slashed_amounts: &mut BTreeMap<Epoch, token::Amount>,
) -> storage_api::Result<()>
where
    S: StorageRead,
{
    tracing::debug!(
        "\nSlashing redelegation amount {} - bond start {} and \
         redel_bond_start {} - at rate {}\n",
        amount.to_string_native(),
        bond_start,
        redel_bond_start,
        slash_rate
    );

    let infraction_epoch =
        current_epoch - params.slash_processing_epoch_offset();

    // Slash redelegation destination validator from the next epoch only
    // as they won't be jailed
    let set_update_epoch = current_epoch.next();

    let mut init_tot_unbonded =
        Epoch::iter_bounds_inclusive(infraction_epoch.next(), set_update_epoch)
            .map(|epoch| {
                let redelegated_unbonded = total_redelegated_unbonded
                    .at(&epoch)
                    .at(&redel_bond_start)
                    .at(src_validator)
                    .get(storage, &bond_start)?
                    .unwrap_or_default();
                Ok(redelegated_unbonded)
            })
            .sum::<storage_api::Result<token::Amount>>()?;

    for epoch in Epoch::iter_range(set_update_epoch, params.pipeline_len) {
        let updated_total_unbonded = {
            let redelegated_unbonded = total_redelegated_unbonded
                .at(&epoch)
                .at(&redel_bond_start)
                .at(src_validator)
                .get(storage, &bond_start)?
                .unwrap_or_default();
            init_tot_unbonded + redelegated_unbonded
        };

        let list_slashes = slashes
            .iter(storage)?
            .map(Result::unwrap)
            .filter(|slash| {
                params.in_redelegation_slashing_window(
                    slash.epoch,
                    params.redelegation_start_epoch_from_end(redel_bond_start),
                    redel_bond_start,
                ) && bond_start <= slash.epoch
                    && slash.epoch + params.slash_processing_epoch_offset()
                    // We're looking for slashes that were processed before or in the epoch
                    // in which slashes that are currently being processed
                    // occurred. Because we're slashing in the beginning of an
                    // epoch, we're also taking slashes that were processed in
                    // the infraction epoch as they would still be processed
                    // before any infraction occurred.
                        <= infraction_epoch
            })
            .collect::<Vec<_>>();

        let slashable_amount = amount
            .checked_sub(updated_total_unbonded)
            .unwrap_or_default();

        let slashed =
            apply_list_slashes(params, &list_slashes, slashable_amount)
                .mul_ceil(slash_rate);

        let list_slashes = slashes
            .iter(storage)?
            .map(Result::unwrap)
            .filter(|slash| {
                params.in_redelegation_slashing_window(
                    slash.epoch,
                    params.redelegation_start_epoch_from_end(redel_bond_start),
                    redel_bond_start,
                ) && bond_start <= slash.epoch
            })
            .collect::<Vec<_>>();

        let slashable_stake =
            apply_list_slashes(params, &list_slashes, slashable_amount)
                .mul_ceil(slash_rate);

        init_tot_unbonded = updated_total_unbonded;
        let to_slash = cmp::min(slashed, slashable_stake);
        if !to_slash.is_zero() {
            let map_value = slashed_amounts.entry(epoch).or_default();
            *map_value += to_slash;
        }
    }

    Ok(())
}

/// Computes for a given validator and a slash how much should be slashed at all
/// epochs between the currentå epoch (curEpoch) + 1 and the current epoch + 1 +
/// PIPELINE_OFFSET, accounting for any tokens already unbonded.
///
/// - `validator` - the misbehaving validator.
/// - `slash_rate` - the rate of the slash being processed.
/// - `slashed_amounts_map` - a map from epoch to already processed slash
///   amounts.
///
/// Returns a map that adds any newly processed slash amount to
/// `slashed_amounts_map`.
// `def slashValidator`
fn slash_validator<S>(
    storage: &S,
    params: &OwnedPosParams,
    validator: &Address,
    slash_rate: Dec,
    current_epoch: Epoch,
    slashed_amounts_map: &BTreeMap<Epoch, token::Amount>,
) -> storage_api::Result<BTreeMap<Epoch, token::Amount>>
where
    S: StorageRead,
{
    tracing::debug!("Slashing validator {} at rate {}", validator, slash_rate);
    let infraction_epoch =
        current_epoch - params.slash_processing_epoch_offset();

    let total_unbonded = total_unbonded_handle(validator);
    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(validator);
    let total_bonded = total_bonded_handle(validator);
    let total_redelegated_bonded =
        validator_total_redelegated_bonded_handle(validator);

    let mut slashed_amounts = slashed_amounts_map.clone();

    let mut tot_bonds = total_bonded
        .get_data_handler()
        .iter(storage)?
        .map(Result::unwrap)
        .filter(|&(epoch, bonded)| {
            epoch <= infraction_epoch && bonded > 0.into()
        })
        .collect::<BTreeMap<_, _>>();

    let mut redelegated_bonds = tot_bonds
        .keys()
        .filter(|&epoch| {
            !total_redelegated_bonded
                .at(epoch)
                .is_empty(storage)
                .unwrap()
        })
        .map(|epoch| {
            let tot_redel_bonded = total_redelegated_bonded
                .at(epoch)
                .collect_map(storage)
                .unwrap();
            (*epoch, tot_redel_bonded)
        })
        .collect::<BTreeMap<_, _>>();

    let mut sum = token::Amount::zero();

    let eps = current_epoch
        .iter_range(params.pipeline_len)
        .collect::<Vec<_>>();
    for epoch in eps.into_iter().rev() {
        let amount = tot_bonds.iter().fold(
            token::Amount::zero(),
            |acc, (bond_start, bond_amount)| {
                acc + compute_slash_bond_at_epoch(
                    storage,
                    params,
                    validator,
                    epoch,
                    infraction_epoch,
                    *bond_start,
                    *bond_amount,
                    redelegated_bonds.get(bond_start),
                    slash_rate,
                )
                .unwrap()
            },
        );

        let new_bonds = total_unbonded.at(&epoch);
        tot_bonds = new_bonds
            .collect_map(storage)
            .unwrap()
            .into_iter()
            .filter(|(ep, _)| *ep <= infraction_epoch)
            .collect::<BTreeMap<_, _>>();

        let new_redelegated_bonds = tot_bonds
            .keys()
            .filter(|&ep| {
                !total_redelegated_unbonded.at(ep).is_empty(storage).unwrap()
            })
            .map(|ep| {
                (
                    *ep,
                    total_redelegated_unbonded
                        .at(&epoch)
                        .at(ep)
                        .collect_map(storage)
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        redelegated_bonds = new_redelegated_bonds;

        // `newSum`
        sum += amount;

        // `newSlashesMap`
        let cur = slashed_amounts.entry(epoch).or_default();
        *cur += sum;
    }
    // Hack - should this be done differently? (think this is safe)
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let last_amt = slashed_amounts
        .get(&pipeline_epoch.prev())
        .cloned()
        .unwrap();
    slashed_amounts.insert(pipeline_epoch, last_amt);

    Ok(slashed_amounts)
}

/// Get the remaining token amount in a bond after applying a set of slashes.
///
/// - `validator` - the bond's validator
/// - `epoch` - the latest slash epoch to consider.
/// - `start` - the start epoch of the bond
/// - `redelegated_bonds`
fn compute_bond_at_epoch<S>(
    storage: &S,
    params: &OwnedPosParams,
    validator: &Address,
    epoch: Epoch,
    start: Epoch,
    amount: token::Amount,
    redelegated_bonds: Option<&EagerRedelegatedBondsMap>,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    let list_slashes = validator_slashes_handle(validator)
        .iter(storage)?
        .map(Result::unwrap)
        .filter(|slash| {
            start <= slash.epoch
                && slash.epoch + params.slash_processing_epoch_offset() <= epoch
        })
        .collect::<Vec<_>>();

    let slash_epoch_filter =
        |e: Epoch| e + params.slash_processing_epoch_offset() <= epoch;

    let result_fold = redelegated_bonds
        .map(|redelegated_bonds| {
            fold_and_slash_redelegated_bonds(
                storage,
                params,
                redelegated_bonds,
                start,
                &list_slashes,
                slash_epoch_filter,
            )
        })
        .unwrap_or_default();

    let total_not_redelegated = amount - result_fold.total_redelegated;
    let after_not_redelegated =
        apply_list_slashes(params, &list_slashes, total_not_redelegated);

    Ok(after_not_redelegated + result_fold.total_after_slashing)
}

/// Uses `fn compute_bond_at_epoch` to compute the token amount to slash in
/// order to prevent overslashing.
#[allow(clippy::too_many_arguments)]
fn compute_slash_bond_at_epoch<S>(
    storage: &S,
    params: &OwnedPosParams,
    validator: &Address,
    epoch: Epoch,
    infraction_epoch: Epoch,
    bond_start: Epoch,
    bond_amount: token::Amount,
    redelegated_bonds: Option<&EagerRedelegatedBondsMap>,
    slash_rate: Dec,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    let amount_due = compute_bond_at_epoch(
        storage,
        params,
        validator,
        infraction_epoch,
        bond_start,
        bond_amount,
        redelegated_bonds,
    )?
    .mul_ceil(slash_rate);
    let slashable_amount = compute_bond_at_epoch(
        storage,
        params,
        validator,
        epoch,
        bond_start,
        bond_amount,
        redelegated_bonds,
    )?;
    Ok(cmp::min(amount_due, slashable_amount))
}

/// Unjail a validator that is currently jailed.
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
        let state =
            validator_state_handle(validator).get(storage, epoch, &params)?;
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
    let last_slash_epoch = read_validator_last_slash_epoch(storage, validator)?;
    if let Some(last_slash_epoch) = last_slash_epoch {
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
    }

    // Re-insert the validator into the validator set and update its state
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let stake =
        read_validator_stake(storage, &params, validator, pipeline_epoch)?;

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

/// Find the total amount of tokens staked at the given `epoch`,
/// belonging to the set of consensus validators.
pub fn get_total_consensus_stake<S>(
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
#[allow(dead_code)]
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
            let cur_rate = slashes.entry(slash.epoch).or_default();
            *cur_rate = cmp::min(*cur_rate + slash.rate, Dec::one());
        }
    }
    Ok(slashes)
}

/// Redelegate bonded tokens from a source validator to a destination validator
pub fn redelegate_tokens<S>(
    storage: &mut S,
    delegator: &Address,
    src_validator: &Address,
    dest_validator: &Address,
    current_epoch: Epoch,
    amount: token::Amount,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    tracing::debug!(
        "Delegator {} redelegating {} tokens from {} to {}",
        delegator,
        amount.to_string_native(),
        src_validator,
        dest_validator
    );
    if amount.is_zero() {
        return Ok(());
    }

    // The src and dest validators must be different
    if src_validator == dest_validator {
        return Err(RedelegationError::RedelegationSrcEqDest.into());
    }

    // The delegator must not be a validator
    if is_validator(storage, delegator)? {
        return Err(RedelegationError::DelegatorIsValidator.into());
    }

    // The src and dest validators must actually be validators
    if !is_validator(storage, src_validator)? {
        return Err(
            RedelegationError::NotAValidator(src_validator.clone()).into()
        );
    }
    if !is_validator(storage, dest_validator)? {
        return Err(
            RedelegationError::NotAValidator(dest_validator.clone()).into()
        );
    }

    let params = read_pos_params(storage)?;
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let src_redel_end_epoch =
        validator_incoming_redelegations_handle(src_validator)
            .get(storage, delegator)?;

    // Forbid chained redelegations. A redelegation is "chained" if:
    // 1. the source validator holds bonded tokens that themselves were
    // redelegated to the src validator
    // 2. given the latest epoch at which the most recently redelegated tokens
    // started contributing to the src validator's voting power, these tokens
    // cannot be slashed anymore
    let is_not_chained = if let Some(end_epoch) = src_redel_end_epoch {
        let last_contrib_epoch = end_epoch.prev();
        // If the source validator's slashes that would cause slash on
        // redelegation are now outdated (would have to be processed before or
        // on start of the current epoch), the redelegation can be redelegated
        // again
        last_contrib_epoch + params.slash_processing_epoch_offset()
            <= current_epoch
    } else {
        true
    };
    if !is_not_chained {
        return Err(RedelegationError::IsChainedRedelegation.into());
    }

    // Unbond the redelegated tokens from the src validator.
    // `resultUnbond` in quint
    let result_unbond = unbond_tokens(
        storage,
        Some(delegator),
        src_validator,
        amount,
        current_epoch,
        true,
    )?;

    // The unbonded amount after slashing is what is going to be redelegated.
    // `amountAfterSlashing`
    let amount_after_slashing = result_unbond.sum;
    tracing::debug!(
        "Redelegated amount after slashing: {}",
        amount_after_slashing.to_string_native()
    );

    // Add incoming redelegated bonds to the dest validator.
    // `updatedRedelegatedBonds` with updates to delegatorState
    // `redelegatedBonded`
    let redelegated_bonds = delegator_redelegated_bonds_handle(delegator)
        .at(dest_validator)
        .at(&pipeline_epoch)
        .at(src_validator);
    for (&epoch, &unbonded_amount) in result_unbond.epoch_map.iter() {
        redelegated_bonds.update(storage, epoch, |current| {
            current.unwrap_or_default() + unbonded_amount
        })?;
    }

    if tracing::level_enabled!(tracing::Level::DEBUG) {
        let bonds = find_bonds(storage, delegator, dest_validator)?;
        tracing::debug!("\nRedeleg dest bonds before incrementing: {bonds:#?}");
    }

    // Add a bond delta to the destination.
    if !amount_after_slashing.is_zero() {
        // `updatedDelegator` with updates to `bonded`
        let bond_handle = bond_handle(delegator, dest_validator);
        bond_handle.add(
            storage,
            amount_after_slashing,
            current_epoch,
            params.pipeline_len,
        )?;
        // `updatedDestValidator` --> `with("totalVBonded")`
        // Add the amount to the dest validator total bonded
        let dest_total_bonded = total_bonded_handle(dest_validator);
        dest_total_bonded.add(
            storage,
            amount_after_slashing,
            current_epoch,
            params.pipeline_len,
        )?;
    }

    if tracing::level_enabled!(tracing::Level::DEBUG) {
        let bonds = find_bonds(storage, delegator, dest_validator)?;
        tracing::debug!("\nRedeleg dest bonds after incrementing: {bonds:#?}");
    }

    // Add outgoing redelegation to the src validator.
    // `updateOutgoingRedelegations` with `updatedSrcValidator`
    let outgoing_redelegations =
        validator_outgoing_redelegations_handle(src_validator)
            .at(dest_validator);
    for (start, &unbonded_amount) in result_unbond.epoch_map.iter() {
        outgoing_redelegations.at(start).update(
            storage,
            current_epoch,
            |current| current.unwrap_or_default() + unbonded_amount,
        )?;
    }

    // Add the amount to the dest validator total redelegated bonds.
    let dest_total_redelegated_bonded =
        validator_total_redelegated_bonded_handle(dest_validator)
            .at(&pipeline_epoch)
            .at(src_validator);
    for (&epoch, &amount) in &result_unbond.epoch_map {
        dest_total_redelegated_bonded.update(storage, epoch, |current| {
            current.unwrap_or_default() + amount
        })?;
    }

    // Set the epoch of the validator incoming redelegation from this delegator
    let dest_incoming_redelegations =
        validator_incoming_redelegations_handle(dest_validator);
    dest_incoming_redelegations.insert(
        storage,
        delegator.clone(),
        pipeline_epoch,
    )?;

    // Update validator set for dest validator
    let is_jailed_or_inactive_at_pipeline = matches!(
        validator_state_handle(dest_validator).get(
            storage,
            pipeline_epoch,
            &params
        )?,
        Some(ValidatorState::Jailed) | Some(ValidatorState::Inactive)
    );
    if !is_jailed_or_inactive_at_pipeline {
        update_validator_set(
            storage,
            &params,
            dest_validator,
            amount_after_slashing.change(),
            current_epoch,
            None,
        )?;
    }

    // Update deltas
    update_validator_deltas(
        storage,
        &params,
        dest_validator,
        amount_after_slashing.change(),
        current_epoch,
        None,
    )?;
    update_total_deltas(
        storage,
        &params,
        amount_after_slashing.change(),
        current_epoch,
        None,
    )?;

    Ok(())
}

/// Deactivate a validator by removing it from any validator sets. A validator
/// can only be deactivated if it is not jailed or already inactive.
pub fn deactivate_validator<S>(
    storage: &mut S,
    validator: &Address,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let params = read_pos_params(storage)?;
    let pipeline_epoch = current_epoch + params.pipeline_len;

    let pipeline_state = match validator_state_handle(validator).get(
        storage,
        pipeline_epoch,
        &params,
    )? {
        Some(state) => state,
        None => {
            return Err(
                DeactivationError::NotAValidator(validator.clone()).into()
            );
        }
    };

    let pipeline_stake =
        read_validator_stake(storage, &params, validator, pipeline_epoch)?;

    // Remove the validator from the validator set. If it is in the consensus
    // set, promote the next validator.
    match pipeline_state {
        ValidatorState::Consensus => deactivate_consensus_validator(
            storage,
            validator,
            pipeline_epoch,
            pipeline_stake,
        )?,

        ValidatorState::BelowCapacity => {
            let below_capacity_set = below_capacity_validator_set_handle()
                .at(&pipeline_epoch)
                .at(&pipeline_stake.into());
            // TODO: handle the unwrap better here
            let val_position = validator_set_positions_handle()
                .at(&pipeline_epoch)
                .get(storage, validator)?
                .unwrap();
            let removed = below_capacity_set.remove(storage, &val_position)?;
            debug_assert_eq!(removed, Some(validator.clone()));

            // Remove position
            validator_set_positions_handle()
                .at(&pipeline_epoch)
                .remove(storage, validator)?;
        }
        ValidatorState::BelowThreshold => {}
        ValidatorState::Inactive => {
            return Err(DeactivationError::AlreadyInactive(
                validator.clone(),
                pipeline_epoch,
            )
            .into());
        }
        ValidatorState::Jailed => {
            return Err(DeactivationError::ValidatorIsJailed(
                validator.clone(),
                pipeline_epoch,
            )
            .into());
        }
    }

    // Set the state to inactive
    validator_state_handle(validator).set(
        storage,
        ValidatorState::Inactive,
        current_epoch,
        params.pipeline_len,
    )?;

    Ok(())
}

fn deactivate_consensus_validator<S>(
    storage: &mut S,

    validator: &Address,
    target_epoch: Epoch,
    stake: token::Amount,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let consensus_set = consensus_validator_set_handle()
        .at(&target_epoch)
        .at(&stake);
    // TODO: handle the unwrap better here
    let val_position = validator_set_positions_handle()
        .at(&target_epoch)
        .get(storage, validator)?
        .unwrap();
    let removed = consensus_set.remove(storage, &val_position)?;
    debug_assert_eq!(removed, Some(validator.clone()));

    // Remove position
    validator_set_positions_handle()
        .at(&target_epoch)
        .remove(storage, validator)?;

    // Now promote the next below-capacity validator to the consensus
    // set
    let below_cap_set = below_capacity_validator_set_handle().at(&target_epoch);
    let max_below_capacity_validator_amount =
        get_max_below_capacity_validator_amount(&below_cap_set, storage)?;

    if let Some(max_bc_amount) = max_below_capacity_validator_amount {
        let below_cap_vals_max = below_cap_set.at(&max_bc_amount.into());
        let lowest_position =
            find_first_position(&below_cap_vals_max, storage)?.unwrap();
        let removed_max_below_capacity = below_cap_vals_max
            .remove(storage, &lowest_position)?
            .expect("Must have been removed");

        insert_validator_into_set(
            &consensus_validator_set_handle()
                .at(&target_epoch)
                .at(&max_bc_amount),
            storage,
            &target_epoch,
            &removed_max_below_capacity,
        )?;
        validator_state_handle(&removed_max_below_capacity).set(
            storage,
            ValidatorState::Consensus,
            target_epoch,
            0,
        )?;
    }

    Ok(())
}

/// Re-activate an inactive validator
pub fn reactivate_validator<S>(
    storage: &mut S,
    validator: &Address,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let params = read_pos_params(storage)?;
    let pipeline_epoch = current_epoch + params.pipeline_len;

    // Make sure state is Inactive at every epoch up through the pipeline
    for epoch in Epoch::iter_bounds_inclusive(current_epoch, pipeline_epoch) {
        let state =
            validator_state_handle(validator).get(storage, epoch, &params)?;
        if let Some(state) = state {
            if state != ValidatorState::Inactive {
                return Err(ReactivationError::NotInactive(
                    validator.clone(),
                    epoch,
                )
                .into());
            }
        } else {
            return Err(ReactivationError::NoStateFound(
                validator.clone(),
                epoch,
            )
            .into());
        }
    }

    // Check to see if the validator should be jailed upon a reactivation. This
    // may occur if a validator is deactivated but then an infraction is
    // discovered later.
    let last_slash_epoch = read_validator_last_slash_epoch(storage, validator)?;
    if let Some(last_slash_epoch) = last_slash_epoch {
        let eligible_epoch =
            last_slash_epoch + params.slash_processing_epoch_offset();
        if current_epoch < eligible_epoch {
            // The validator should be set back to jailed
            validator_state_handle(validator).set(
                storage,
                ValidatorState::Jailed,
                pipeline_epoch,
                0,
            )?;
            return Ok(());
        }
    }

    // Determine which validator set the validator should be added to again
    let stake =
        read_validator_stake(storage, &params, validator, pipeline_epoch)?;

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

/// Remove liveness data from storage for all validators that are not in the
/// current consensus validator set.
pub fn prune_liveness_data<S>(
    storage: &mut S,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let consensus_validators =
        read_consensus_validator_set_addresses(storage, current_epoch)?;
    let liveness_missed_votes = liveness_missed_votes_handle();
    let liveness_sum_missed_votes = liveness_sum_missed_votes_handle();

    let validators_to_prune = liveness_sum_missed_votes
        .iter(storage)?
        .filter_map(|entry| {
            let (address, _) = entry.ok()?;

            if consensus_validators.contains(&address) {
                None
            } else {
                Some(address)
            }
        })
        .collect::<Vec<Address>>();

    for validator in &validators_to_prune {
        liveness_missed_votes.remove_all(storage, validator)?;
        liveness_sum_missed_votes.remove(storage, validator)?;
    }

    Ok(())
}

/// Record the liveness data of the consensus validators
pub fn record_liveness_data<S>(
    storage: &mut S,
    votes: &[VoteInfo],
    votes_epoch: Epoch,
    votes_height: BlockHeight,
    pos_params: &PosParams,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let consensus_validators =
        read_consensus_validator_set_addresses(storage, votes_epoch)?;
    let liveness_missed_votes = liveness_missed_votes_handle();
    let liveness_sum_missed_votes = liveness_sum_missed_votes_handle();

    // Get the addresses of the validators who voted
    let vote_addresses = votes
        .iter()
        .map(|vote| (&vote.validator_address))
        .collect::<HashSet<&Address>>();

    let height_to_prune =
        votes_height.0.checked_sub(pos_params.liveness_window_check);

    for cons_validator in consensus_validators.into_iter() {
        // Prune old vote (only need to look for the block height that was just
        // pushed out of the sliding window)
        if let Some(prune_height) = height_to_prune {
            let pruned_missing_vote = liveness_missed_votes
                .at(&cons_validator)
                .remove(storage, &prune_height)?;

            if pruned_missing_vote {
                // Update liveness data
                liveness_sum_missed_votes.update(
                    storage,
                    cons_validator.clone(),
                    |missed_votes| missed_votes.unwrap() - 1,
                )?;
            }
        }

        // Evaluate new vote
        if !vote_addresses.contains(&cons_validator) {
            // Insert the height of the missing vote in storage
            liveness_missed_votes
                .at(&cons_validator)
                .insert(storage, votes_height.0)?;

            // Update liveness data
            liveness_sum_missed_votes.update(
                storage,
                cons_validator,
                |missed_votes| {
                    match missed_votes {
                        Some(missed_votes) => missed_votes + 1,
                        None => {
                            // Missing liveness data for the validator (newly
                            // added to the consensus
                            // set), initialize it
                            1
                        }
                    }
                },
            )?;
        } else {
            // Initialize any new consensus validator who has signed the first
            // block
            if !liveness_sum_missed_votes.contains(storage, &cons_validator)? {
                liveness_sum_missed_votes.insert(storage, cons_validator, 0)?;
            }
        }
    }

    Ok(())
}

/// Jail validators who failed to match the liveness threshold
pub fn jail_for_liveness<S>(
    storage: &mut S,
    params: &PosParams,
    current_epoch: Epoch,
    jail_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    // Derive the actual missing votes limit from the percentage
    let missing_votes_threshold = ((Dec::one() - params.liveness_threshold)
        * params.liveness_window_check)
        .to_uint()
        .ok_or_else(|| {
            storage_api::Error::SimpleMessage(
                "Found negative liveness threshold",
            )
        })?
        .as_u64();

    // Jail inactive validators
    let validators_to_jail = liveness_sum_missed_votes_handle()
        .iter(storage)?
        .filter_map(|entry| {
            let (address, missed_votes) = entry.ok()?;

            // Check if validator failed to match the threshold and jail
            // them
            if missed_votes >= missing_votes_threshold {
                Some(address)
            } else {
                None
            }
        })
        .collect::<HashSet<_>>();

    for validator in &validators_to_jail {
        let state_jail_epoch = validator_state_handle(validator)
            .get(storage, jail_epoch, params)?
            .expect("Validator should have a state for the jail epoch");
        if state_jail_epoch == ValidatorState::Jailed {
            continue;
        }
        tracing::info!(
            "Jailing validator {} starting in epoch {} for missing too many \
             votes to ensure liveness",
            validator,
            jail_epoch,
        );
        jail_validator(storage, params, validator, current_epoch, jail_epoch)?;
    }

    Ok(())
}

#[cfg(any(test, feature = "testing"))]
/// PoS related utility functions to help set up tests.
pub mod test_utils {
    use namada_core::ledger::storage_api;
    use namada_core::ledger::storage_api::token::credit_tokens;
    use namada_core::ledger::storage_api::{StorageRead, StorageWrite};

    use super::*;
    use crate::parameters::PosParams;
    use crate::types::GenesisValidator;

    /// Helper function to initialize storage with PoS data
    /// about validators for tests.
    pub fn init_genesis_helper<S>(
        storage: &mut S,
        params: &PosParams,
        validators: impl Iterator<Item = GenesisValidator>,
        current_epoch: namada_core::types::storage::Epoch,
    ) -> storage_api::Result<()>
    where
        S: StorageRead + StorageWrite,
    {
        init_genesis(storage, params, current_epoch)?;
        for GenesisValidator {
            address,
            consensus_key,
            protocol_key,
            eth_cold_key,
            eth_hot_key,
            commission_rate,
            max_commission_rate_change,
            tokens,
            metadata,
        } in validators
        {
            become_validator(
                storage,
                BecomeValidator {
                    params,
                    address: &address,
                    consensus_key: &consensus_key,
                    protocol_key: &protocol_key,
                    eth_cold_key: &eth_cold_key,
                    eth_hot_key: &eth_hot_key,
                    current_epoch,
                    commission_rate,
                    max_commission_rate_change,
                    metadata,
                    offset_opt: Some(0),
                },
            )?;
            // Credit token amount to be bonded to the validator address so it
            // can be bonded
            let staking_token = staking_token_address(storage);
            credit_tokens(storage, &staking_token, &address, tokens)?;

            bond_tokens(
                storage,
                None,
                &address,
                tokens,
                current_epoch,
                Some(0),
            )?;
        }
        // Store the total consensus validator stake to storage
        compute_and_store_total_consensus_stake(storage, current_epoch)?;

        // Copy validator sets and positions
        copy_genesis_validator_sets(storage, params, current_epoch)?;

        Ok(())
    }

    /// Init PoS genesis wrapper helper that also initializes gov params that
    /// are used in PoS with default values.
    pub fn test_init_genesis<S>(
        storage: &mut S,
        owned: OwnedPosParams,
        validators: impl Iterator<Item = GenesisValidator> + Clone,
        current_epoch: namada_core::types::storage::Epoch,
    ) -> storage_api::Result<PosParams>
    where
        S: StorageRead + StorageWrite,
    {
        let gov_params = namada_core::ledger::governance::parameters::GovernanceParameters::default();
        gov_params.init_storage(storage)?;
        let params = crate::read_non_pos_owned_params(storage, owned)?;
        init_genesis_helper(storage, &params, validators, current_epoch)?;
        Ok(params)
    }
}

/// Read PoS validator's email.
pub fn read_validator_email<S>(
    storage: &S,
    validator: &Address,
) -> storage_api::Result<Option<String>>
where
    S: StorageRead,
{
    storage.read(&validator_email_key(validator))
}

/// Write PoS validator's email. The email cannot be removed, so an empty string
/// will result in an error.
pub fn write_validator_email<S>(
    storage: &mut S,
    validator: &Address,
    email: &String,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = validator_email_key(validator);
    if email.is_empty() {
        Err(MetadataError::CannotRemoveEmail.into())
    } else {
        storage.write(&key, email)
    }
}

/// Read PoS validator's description.
pub fn read_validator_description<S>(
    storage: &S,
    validator: &Address,
) -> storage_api::Result<Option<String>>
where
    S: StorageRead,
{
    storage.read(&validator_description_key(validator))
}

/// Write PoS validator's description. If the provided arg is an empty string,
/// remove the data.
pub fn write_validator_description<S>(
    storage: &mut S,
    validator: &Address,
    description: &String,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = validator_description_key(validator);
    if description.is_empty() {
        storage.delete(&key)
    } else {
        storage.write(&key, description)
    }
}

/// Read PoS validator's website.
pub fn read_validator_website<S>(
    storage: &S,
    validator: &Address,
) -> storage_api::Result<Option<String>>
where
    S: StorageRead,
{
    storage.read(&validator_website_key(validator))
}

/// Write PoS validator's website. If the provided arg is an empty string,
/// remove the data.
pub fn write_validator_website<S>(
    storage: &mut S,
    validator: &Address,
    website: &String,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = validator_website_key(validator);
    if website.is_empty() {
        storage.delete(&key)
    } else {
        storage.write(&key, website)
    }
}

/// Read PoS validator's discord handle.
pub fn read_validator_discord_handle<S>(
    storage: &S,
    validator: &Address,
) -> storage_api::Result<Option<String>>
where
    S: StorageRead,
{
    storage.read(&validator_discord_key(validator))
}

/// Write PoS validator's discord handle. If the provided arg is an empty
/// string, remove the data.
pub fn write_validator_discord_handle<S>(
    storage: &mut S,
    validator: &Address,
    discord_handle: &String,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = validator_discord_key(validator);
    if discord_handle.is_empty() {
        storage.delete(&key)
    } else {
        storage.write(&key, discord_handle)
    }
}

/// Write validator's metadata.
pub fn write_validator_metadata<S>(
    storage: &mut S,
    validator: &Address,
    metadata: &ValidatorMetaData,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    // Email is the only required field in the metadata
    write_validator_email(storage, validator, &metadata.email)?;

    if let Some(description) = metadata.description.as_ref() {
        write_validator_description(storage, validator, description)?;
    }
    if let Some(website) = metadata.website.as_ref() {
        write_validator_website(storage, validator, website)?;
    }
    if let Some(discord) = metadata.discord_handle.as_ref() {
        write_validator_discord_handle(storage, validator, discord)?;
    }
    Ok(())
}

/// Change validator's metadata. In addition to changing any of the data from
/// [`ValidatorMetaData`], the validator's commission rate can be changed within
/// here as well.
#[allow(clippy::too_many_arguments)]
pub fn change_validator_metadata<S>(
    storage: &mut S,
    validator: &Address,
    email: Option<String>,
    description: Option<String>,
    website: Option<String>,
    discord_handle: Option<String>,
    commission_rate: Option<Dec>,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    if let Some(email) = email {
        write_validator_email(storage, validator, &email)?;
    }
    if let Some(description) = description {
        write_validator_description(storage, validator, &description)?;
    }
    if let Some(website) = website {
        write_validator_website(storage, validator, &website)?;
    }
    if let Some(discord) = discord_handle {
        write_validator_discord_handle(storage, validator, &discord)?;
    }
    if let Some(commission_rate) = commission_rate {
        change_validator_commission_rate(
            storage,
            validator,
            commission_rate,
            current_epoch,
        )?;
    }
    Ok(())
}

/// Compute the current available rewards amount due only to existing bonds.
/// This does not include pending rewards held in the rewards counter due to
/// unbonds and redelegations.
pub fn compute_current_rewards_from_bonds<S>(
    storage: &S,
    source: &Address,
    validator: &Address,
    current_epoch: Epoch,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    if current_epoch == Epoch::default() {
        // Nothing to claim in the first epoch
        return Ok(token::Amount::zero());
    }

    let last_claim_epoch =
        get_last_reward_claim_epoch(storage, source, validator)?;
    if let Some(last_epoch) = last_claim_epoch {
        if last_epoch == current_epoch {
            // Already claimed in this epoch
            return Ok(token::Amount::zero());
        }
    }

    let mut reward_tokens = token::Amount::zero();

    // Want to claim from `last_claim_epoch` to `current_epoch.prev()` since
    // rewards are computed at the end of an epoch
    let (claim_start, claim_end) = (
        last_claim_epoch.unwrap_or_default(),
        // Safe because of the check above
        current_epoch.prev(),
    );
    let bond_amounts = bond_amounts_for_rewards(
        storage,
        &BondId {
            source: source.clone(),
            validator: validator.clone(),
        },
        claim_start,
        claim_end,
    )?;

    let rewards_products = validator_rewards_products_handle(validator);
    for (ep, bond_amount) in bond_amounts {
        debug_assert!(ep >= claim_start);
        debug_assert!(ep <= claim_end);
        let rp = rewards_products.get(storage, &ep)?.unwrap_or_default();
        let reward = rp * bond_amount;
        reward_tokens += reward;
    }

    Ok(reward_tokens)
}

/// Claim available rewards, triggering an immediate transfer of tokens from the
/// PoS account to the source address.
pub fn claim_reward_tokens<S>(
    storage: &mut S,
    source: Option<&Address>,
    validator: &Address,
    current_epoch: Epoch,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead + StorageWrite,
{
    tracing::debug!("Claiming rewards in epoch {current_epoch}");

    let source = source.cloned().unwrap_or_else(|| validator.clone());
    tracing::debug!("Source {} --> Validator {}", source, validator);

    let mut reward_tokens = compute_current_rewards_from_bonds(
        storage,
        &source,
        validator,
        current_epoch,
    )?;

    // Add reward tokens tallied during previous withdrawals
    reward_tokens += take_rewards_from_counter(storage, &source, validator)?;

    // Update the last claim epoch in storage
    write_last_reward_claim_epoch(storage, &source, validator, current_epoch)?;

    // Transfer the bonded tokens from PoS to the source
    let staking_token = staking_token_address(storage);
    token::transfer(storage, &staking_token, &ADDRESS, &source, reward_tokens)?;

    Ok(reward_tokens)
}

/// Query the amount of available reward tokens for a given bond.
pub fn query_reward_tokens<S>(
    storage: &S,
    source: Option<&Address>,
    validator: &Address,
    current_epoch: Epoch,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    let source = source.cloned().unwrap_or_else(|| validator.clone());
    let rewards_from_bonds = compute_current_rewards_from_bonds(
        storage,
        &source,
        validator,
        current_epoch,
    )?;

    let rewards_from_counter =
        read_rewards_counter(storage, &source, validator)?;

    Ok(rewards_from_bonds + rewards_from_counter)
}

/// Get the last epoch in which rewards were claimed from storage, if any
pub fn get_last_reward_claim_epoch<S>(
    storage: &S,
    delegator: &Address,
    validator: &Address,
) -> storage_api::Result<Option<Epoch>>
where
    S: StorageRead,
{
    let key = last_pos_reward_claim_epoch_key(delegator, validator);
    storage.read(&key)
}

fn write_last_reward_claim_epoch<S>(
    storage: &mut S,
    delegator: &Address,
    validator: &Address,
    epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = last_pos_reward_claim_epoch_key(delegator, validator);
    storage.write(&key, epoch)
}

/// Read the current token value in the rewards counter.
fn read_rewards_counter<S>(
    storage: &S,
    source: &Address,
    validator: &Address,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    let key = rewards_counter_key(source, validator);
    Ok(storage.read::<token::Amount>(&key)?.unwrap_or_default())
}

/// Add tokens to a rewards counter.
fn add_rewards_to_counter<S>(
    storage: &mut S,
    source: &Address,
    validator: &Address,
    new_rewards: token::Amount,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = rewards_counter_key(source, validator);
    let current_rewards =
        storage.read::<token::Amount>(&key)?.unwrap_or_default();
    storage.write(&key, current_rewards + new_rewards)
}

/// Take tokens from a rewards counter. Deletes the record after reading.
fn take_rewards_from_counter<S>(
    storage: &mut S,
    source: &Address,
    validator: &Address,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead + StorageWrite,
{
    let key = rewards_counter_key(source, validator);
    let current_rewards =
        storage.read::<token::Amount>(&key)?.unwrap_or_default();
    storage.delete(&key)?;
    Ok(current_rewards)
}

/// Jail a validator by removing it from and updating the validator sets and
/// changing a its state to `Jailed`. Validators are jailed for liveness and for
/// misbehaving.
fn jail_validator<S>(
    storage: &mut S,
    params: &PosParams,
    validator: &Address,
    current_epoch: Epoch,
    validator_set_update_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    tracing::debug!(
        "Jailing validator {} beginning in epoch {}",
        validator,
        validator_set_update_epoch
    );

    // Remove the validator from the set starting at the update epoch and up
    // thru the pipeline epoch.
    let pipeline_epoch = current_epoch + params.pipeline_len;
    for epoch in
        Epoch::iter_bounds_inclusive(validator_set_update_epoch, pipeline_epoch)
    {
        let prev_state = validator_state_handle(validator)
            .get(storage, epoch, params)?
            .expect("Expected to find a valid validator.");
        match prev_state {
            ValidatorState::Consensus => {
                tracing::debug!(
                    "Removing validator from the consensus set in epoch {}",
                    epoch
                );
                let amount_pre =
                    read_validator_stake(storage, params, validator, epoch)?;
                let val_position = validator_set_positions_handle()
                    .at(&epoch)
                    .get(storage, validator)?
                    .expect("Could not find validator's position in storage.");
                let _ = consensus_validator_set_handle()
                    .at(&epoch)
                    .at(&amount_pre)
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
                tracing::debug!(
                    "Removing validator from the below-capacity set in epoch \
                     {}",
                    epoch
                );

                let amount_pre = validator_deltas_handle(validator)
                    .get_sum(storage, epoch, params)?
                    .unwrap_or_default();
                debug_assert!(amount_pre.non_negative());
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
                tracing::debug!(
                    "Setting below-threshold validator as jailed in epoch {}",
                    epoch
                );
            }
            ValidatorState::Inactive => {
                tracing::debug!(
                    "Setting inactive validator as jailed in epoch {}",
                    epoch
                );
            }
            ValidatorState::Jailed => {
                tracing::debug!(
                    "Found evidence for a validator who is already jailed"
                );
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
    Ok(())
}
