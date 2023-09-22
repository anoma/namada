//! PoS functions for reading and writing to storage and lazy collection handles
//! associated with given `storage_key`s.

use namada_core::ledger::storage_api::collections::LazyCollection;
use namada_core::types::address::Address;

use crate::storage_key;
use crate::types::{
    BelowCapacityValidatorSets, BondId, Bonds, CommissionRates,
    ConsensusValidatorSets, DelegatorRedelegatedBonded,
    DelegatorRedelegatedUnbonded, EpochedSlashes, IncomingRedelegations,
    OutgoingRedelegations, RewardsAccumulator, RewardsProducts, Slashes,
    TotalConsensusStakes, TotalDeltas, TotalRedelegatedBonded,
    TotalRedelegatedUnbonded, Unbonds, ValidatorAddresses,
    ValidatorConsensusKeys, ValidatorDeltas, ValidatorEthColdKeys,
    ValidatorEthHotKeys, ValidatorSetPositions, ValidatorStates,
    ValidatorTotalUnbonded,
};

// ---- Storage handles ----

/// Get the storage handle to the epoched consensus validator set
pub fn consensus_validator_set_handle() -> ConsensusValidatorSets {
    let key = storage_key::consensus_validator_set_key();
    ConsensusValidatorSets::open(key)
}

/// Get the storage handle to the epoched below-capacity validator set
pub fn below_capacity_validator_set_handle() -> BelowCapacityValidatorSets {
    let key = storage_key::below_capacity_validator_set_key();
    BelowCapacityValidatorSets::open(key)
}

/// Get the storage handle to a PoS validator's consensus key (used for
/// signing block votes).
pub fn validator_consensus_key_handle(
    validator: &Address,
) -> ValidatorConsensusKeys {
    let key = storage_key::validator_consensus_key_key(validator);
    ValidatorConsensusKeys::open(key)
}

/// Get the storage handle to a PoS validator's eth hot key.
pub fn validator_eth_hot_key_handle(
    validator: &Address,
) -> ValidatorEthHotKeys {
    let key = storage_key::validator_eth_hot_key_key(validator);
    ValidatorEthHotKeys::open(key)
}

/// Get the storage handle to a PoS validator's eth cold key.
pub fn validator_eth_cold_key_handle(
    validator: &Address,
) -> ValidatorEthColdKeys {
    let key = storage_key::validator_eth_cold_key_key(validator);
    ValidatorEthColdKeys::open(key)
}

/// Get the storage handle to the total consensus validator stake
pub fn total_consensus_stake_key_handle() -> TotalConsensusStakes {
    let key = storage_key::total_consensus_stake_key();
    TotalConsensusStakes::open(key)
}

/// Get the storage handle to a PoS validator's state
pub fn validator_state_handle(validator: &Address) -> ValidatorStates {
    let key = storage_key::validator_state_key(validator);
    ValidatorStates::open(key)
}

/// Get the storage handle to a PoS validator's deltas
pub fn validator_deltas_handle(validator: &Address) -> ValidatorDeltas {
    let key = storage_key::validator_deltas_key(validator);
    ValidatorDeltas::open(key)
}

/// Get the storage handle to the total deltas
pub fn total_deltas_handle() -> TotalDeltas {
    let key = storage_key::total_deltas_key();
    TotalDeltas::open(key)
}

/// Get the storage handle to the set of all validators
pub fn validator_addresses_handle() -> ValidatorAddresses {
    let key = storage_key::validator_addresses_key();
    ValidatorAddresses::open(key)
}

/// Get the storage handle to a PoS validator's commission rate
pub fn validator_commission_rate_handle(
    validator: &Address,
) -> CommissionRates {
    let key = storage_key::validator_commission_rate_key(validator);
    CommissionRates::open(key)
}

/// Get the storage handle to a bond, which is dynamically updated with when
/// unbonding
pub fn bond_handle(source: &Address, validator: &Address) -> Bonds {
    let bond_id = BondId {
        source: source.clone(),
        validator: validator.clone(),
    };
    let key = storage_key::bond_key(&bond_id);
    Bonds::open(key)
}

/// Get the storage handle to a validator's total bonds, which are not updated
/// due to unbonding
pub fn total_bonded_handle(validator: &Address) -> Bonds {
    let key = storage_key::validator_total_bonded_key(validator);
    Bonds::open(key)
}

/// Get the storage handle to an unbond
pub fn unbond_handle(source: &Address, validator: &Address) -> Unbonds {
    let bond_id = BondId {
        source: source.clone(),
        validator: validator.clone(),
    };
    let key = storage_key::unbond_key(&bond_id);
    Unbonds::open(key)
}

/// Get the storage handle to a validator's total-unbonded map
pub fn total_unbonded_handle(validator: &Address) -> ValidatorTotalUnbonded {
    let key = storage_key::validator_total_unbonded_key(validator);
    ValidatorTotalUnbonded::open(key)
}

/// Get the storage handle to a PoS validator's deltas
pub fn validator_set_positions_handle() -> ValidatorSetPositions {
    let key = storage_key::validator_set_positions_key();
    ValidatorSetPositions::open(key)
}

/// Get the storage handle to a PoS validator's slashes
pub fn validator_slashes_handle(validator: &Address) -> Slashes {
    let key = storage_key::validator_slashes_key(validator);
    Slashes::open(key)
}

/// Get the storage handle to list of all slashes to be processed and ultimately
/// placed in the `validator_slashes_handle`
pub fn enqueued_slashes_handle() -> EpochedSlashes {
    let key = storage_key::enqueued_slashes_key();
    EpochedSlashes::open(key)
}

/// Get the storage handle to the rewards accumulator for the consensus
/// validators in a given epoch
pub fn rewards_accumulator_handle() -> RewardsAccumulator {
    let key = storage_key::consensus_validator_rewards_accumulator_key();
    RewardsAccumulator::open(key)
}

/// Get the storage handle to a validator's self rewards products
pub fn validator_rewards_products_handle(
    validator: &Address,
) -> RewardsProducts {
    let key = storage_key::validator_self_rewards_product_key(validator);
    RewardsProducts::open(key)
}

/// Get the storage handle to the delegator rewards products associated with a
/// particular validator
pub fn delegator_rewards_products_handle(
    validator: &Address,
) -> RewardsProducts {
    let key = storage_key::validator_delegation_rewards_product_key(validator);
    RewardsProducts::open(key)
}

/// Get the storage handle to a validator's incoming redelegations
pub fn validator_incoming_redelegations_handle(
    validator: &Address,
) -> IncomingRedelegations {
    let key = storage_key::validator_incoming_redelegations_key(validator);
    IncomingRedelegations::open(key)
}

/// Get the storage handle to a validator's outgoing redelegations
pub fn validator_outgoing_redelegations_handle(
    validator: &Address,
) -> OutgoingRedelegations {
    let key = storage_key::validator_outgoing_redelegations_key(validator);
    OutgoingRedelegations::open(key)
}

/// Get the storage handle to a validator's total redelegated bonds
pub fn validator_total_redelegated_bonded_handle(
    validator: &Address,
) -> TotalRedelegatedBonded {
    let key = storage_key::validator_total_redelegated_bonded_key(validator);
    TotalRedelegatedBonded::open(key)
}

/// Get the storage handle to a validator's outgoing redelegations
pub fn validator_total_redelegated_unbonded_handle(
    validator: &Address,
) -> TotalRedelegatedUnbonded {
    let key = storage_key::validator_total_redelegated_unbonded_key(validator);
    TotalRedelegatedUnbonded::open(key)
}

/// Get the storage handle to a delegator's redelegated bonds information
pub fn delegator_redelegated_bonds_handle(
    delegator: &Address,
) -> DelegatorRedelegatedBonded {
    let key = storage_key::delegator_redelegated_bonds_key(delegator);
    DelegatorRedelegatedBonded::open(key)
}

/// Get the storage handle to a delegator's redelegated unbonds information
pub fn delegator_redelegated_unbonds_handle(
    delegator: &Address,
) -> DelegatorRedelegatedUnbonded {
    let key = storage_key::delegator_redelegated_unbonds_key(delegator);
    DelegatorRedelegatedUnbonded::open(key)
}
