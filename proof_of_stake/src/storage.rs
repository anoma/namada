//! Proof-of-Stake storage keys and storage integration.

use namada_core::ledger::storage_api::collections::{lazy_map, lazy_vec};
use namada_core::types::address::Address;
use namada_core::types::storage::{DbKeySeg, Epoch, Key, KeySeg};

use super::ADDRESS;
use crate::epoched::LAZY_MAP_SUB_KEY;
pub use crate::types::*; // TODO: not sure why this needs to be public

const PARAMS_STORAGE_KEY: &str = "params";
const VALIDATOR_STORAGE_PREFIX: &str = "validator";
const VALIDATOR_ADDRESS_RAW_HASH: &str = "address_raw_hash";
const VALIDATOR_CONSENSUS_KEY_STORAGE_KEY: &str = "consensus_key";
const VALIDATOR_STATE_STORAGE_KEY: &str = "state";
const VALIDATOR_DELTAS_STORAGE_KEY: &str = "deltas";
const VALIDATOR_COMMISSION_RATE_STORAGE_KEY: &str = "commission_rate";
const VALIDATOR_MAX_COMMISSION_CHANGE_STORAGE_KEY: &str =
    "max_commission_rate_change";
const VALIDATOR_SELF_REWARDS_PRODUCT_KEY: &str = "validator_rewards_product";
const VALIDATOR_DELEGATION_REWARDS_PRODUCT_KEY: &str =
    "delegation_rewards_product";
const VALIDATOR_LAST_KNOWN_PRODUCT_EPOCH_KEY: &str =
    "last_known_rewards_product_epoch";
const SLASHES_PREFIX: &str = "slash";
const BOND_STORAGE_KEY: &str = "bond";
const UNBOND_STORAGE_KEY: &str = "unbond";
const VALIDATOR_SETS_STORAGE_PREFIX: &str = "validator_sets";
const CONSENSUS_VALIDATOR_SET_STORAGE_KEY: &str = "consensus";
const NUM_CONSENSUS_VALIDATORS_STORAGE_KEY: &str = "num_consensus";
const BELOW_CAPACITY_VALIDATOR_SET_STORAGE_KEY: &str = "below_capacity";
const TOTAL_DELTAS_STORAGE_KEY: &str = "total_deltas";
const VALIDATOR_SET_POSITIONS_KEY: &str = "validator_set_positions";
const LAST_BLOCK_PROPOSER_STORAGE_KEY: &str = "last_block_proposer";
const CURRENT_BLOCK_PROPOSER_STORAGE_KEY: &str = "current_block_proposer";
const CONSENSUS_VALIDATOR_SET_ACCUMULATOR_STORAGE_KEY: &str =
    "validator_rewards_accumulator";

/// Is the given key a PoS storage key?
pub fn is_pos_key(key: &Key) -> bool {
    match &key.segments.get(0) {
        Some(DbKeySeg::AddressSeg(addr)) => addr == &ADDRESS,
        _ => false,
    }
}

/// Storage key for PoS parameters.
pub fn params_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&PARAMS_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for PoS parameters?
pub fn is_params_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)] if addr == &ADDRESS && key == PARAMS_STORAGE_KEY)
}

/// Storage key prefix for validator data.
fn validator_prefix(validator: &Address) -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&VALIDATOR_STORAGE_PREFIX.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&validator.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Storage key for validator's address raw hash for look-up from raw hash of an
/// address to address.
pub fn validator_address_raw_hash_key(raw_hash: impl AsRef<str>) -> Key {
    let raw_hash = raw_hash.as_ref().to_owned();
    Key::from(ADDRESS.to_db_key())
        .push(&VALIDATOR_ADDRESS_RAW_HASH.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&raw_hash)
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's address raw hash?
pub fn is_validator_address_raw_hash_key(key: &Key) -> Option<&str> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(raw_hash),
        ] if addr == &ADDRESS && prefix == VALIDATOR_ADDRESS_RAW_HASH => {
            Some(raw_hash)
        }
        _ => None,
    }
}

/// Storage key for validator's consensus key.
pub fn validator_consensus_key_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_CONSENSUS_KEY_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's consensus key?
pub fn is_validator_consensus_key_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
            DbKeySeg::StringSeg(key),
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && key == VALIDATOR_CONSENSUS_KEY_STORAGE_KEY =>
        {
            Some(validator)
        }
        _ => None,
    }
}

/// Storage key for validator's commission rate.
pub fn validator_commission_rate_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_COMMISSION_RATE_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's commissionr ate?
pub fn is_validator_commission_rate_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
            DbKeySeg::StringSeg(key),
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && key == VALIDATOR_COMMISSION_RATE_STORAGE_KEY =>
        {
            Some(validator)
        }
        _ => None,
    }
}

/// Storage key for validator's maximum commission rate change per epoch.
pub fn validator_max_commission_rate_change_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_MAX_COMMISSION_CHANGE_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's maximum commission rate change per epoch?
pub fn is_validator_max_commission_rate_change_key(
    key: &Key,
) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
            DbKeySeg::StringSeg(key),
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && key == VALIDATOR_MAX_COMMISSION_CHANGE_STORAGE_KEY =>
        {
            Some(validator)
        }
        _ => None,
    }
}

/// Storage key for validator's self rewards products.
pub fn validator_self_rewards_product_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_SELF_REWARDS_PRODUCT_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's self rewards products?
pub fn is_validator_self_rewards_product_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
            DbKeySeg::StringSeg(key),
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && key == VALIDATOR_SELF_REWARDS_PRODUCT_KEY =>
        {
            Some(validator)
        }
        _ => None,
    }
}

/// Storage key for validator's delegation rewards products.
pub fn validator_delegation_rewards_product_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_DELEGATION_REWARDS_PRODUCT_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's delegation rewards products?
pub fn is_validator_delegation_rewards_product_key(
    key: &Key,
) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
            DbKeySeg::StringSeg(key),
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && key == VALIDATOR_DELEGATION_REWARDS_PRODUCT_KEY =>
        {
            Some(validator)
        }
        _ => None,
    }
}

/// Storage key for validator's last known rewards product epoch.
pub fn validator_last_known_product_epoch_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_LAST_KNOWN_PRODUCT_EPOCH_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's last known rewards product epoch?
pub fn is_validator_last_known_product_epoch_key(
    key: &Key,
) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
            DbKeySeg::StringSeg(key),
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && key == VALIDATOR_LAST_KNOWN_PRODUCT_EPOCH_KEY =>
        {
            Some(validator)
        }
        _ => None,
    }
}

/// Storage key for validator's consensus key.
pub fn validator_state_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_STATE_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's state?
pub fn is_validator_state_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
            DbKeySeg::StringSeg(key),
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && key == VALIDATOR_STATE_STORAGE_KEY =>
        {
            Some(validator)
        }
        _ => None,
    }
}

/// Storage key for validator's deltas.
pub fn validator_deltas_key(validator: &Address) -> Key {
    validator_prefix(validator)
        .push(&VALIDATOR_DELTAS_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for validator's total deltas?
pub fn is_validator_deltas_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
            DbKeySeg::StringSeg(key),
            DbKeySeg::StringSeg(lazy_map),
            DbKeySeg::StringSeg(data),
            DbKeySeg::StringSeg(_epoch),
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && key == VALIDATOR_DELTAS_STORAGE_KEY
            && lazy_map == LAZY_MAP_SUB_KEY
            && data == lazy_map::DATA_SUBKEY =>
        {
            Some(validator)
        }
        _ => None,
    }
}

/// Storage prefix for slashes.
pub fn slashes_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&SLASHES_PREFIX.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for validator's slashes.
pub fn validator_slashes_key(validator: &Address) -> Key {
    slashes_prefix()
        .push(&validator.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// NEW: Is storage key for validator's slashes
pub fn is_validator_slashes_key(key: &Key) -> Option<Address> {
    if key.segments.len() >= 5 {
        match &key.segments[..] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(validator),
                DbKeySeg::StringSeg(data),
                DbKeySeg::StringSeg(_index),
            ] if addr == &ADDRESS
                && prefix == SLASHES_PREFIX
                && data == lazy_vec::DATA_SUBKEY =>
            {
                Some(validator.clone())
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Storage key prefix for all bonds.
pub fn bonds_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&BOND_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key prefix for all bonds of the given source address.
pub fn bonds_for_source_prefix(source: &Address) -> Key {
    bonds_prefix()
        .push(&source.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Storage key for a bond with the given ID (source and validator).
pub fn bond_key(bond_id: &BondId) -> Key {
    bonds_for_source_prefix(&bond_id.source)
        .push(&bond_id.validator.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for a bond? Returns the bond ID and bond start epoch if so.
pub fn is_bond_key(key: &Key) -> Option<(BondId, Epoch)> {
    if key.segments.len() >= 7 {
        match &key.segments[..7] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(source),
                DbKeySeg::AddressSeg(validator),
                DbKeySeg::StringSeg(lazy_map),
                DbKeySeg::StringSeg(data),
                DbKeySeg::StringSeg(epoch_str),
            ] if addr == &ADDRESS
                && prefix == BOND_STORAGE_KEY
                && lazy_map == crate::epoched::LAZY_MAP_SUB_KEY
                && data == lazy_map::DATA_SUBKEY =>
            {
                let start = Epoch::parse(epoch_str.clone()).ok()?;
                Some((
                    BondId {
                        source: source.clone(),
                        validator: validator.clone(),
                    },
                    start,
                ))
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Storage key prefix for all unbonds.
pub fn unbonds_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&UNBOND_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key prefix for all unbonds of the given source address.
pub fn unbonds_for_source_prefix(source: &Address) -> Key {
    unbonds_prefix()
        .push(&source.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Storage key for an unbond with the given ID (source and validator).
pub fn unbond_key(bond_id: &BondId) -> Key {
    unbonds_for_source_prefix(&bond_id.source)
        .push(&bond_id.validator.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for an unbond? Returns the bond ID and unbond start and
/// withdraw epoch if it is.
pub fn is_unbond_key(key: &Key) -> Option<(BondId, Epoch, Epoch)> {
    if key.segments.len() >= 8 {
        match &key.segments[..8] {
            [
                DbKeySeg::AddressSeg(addr),
                DbKeySeg::StringSeg(prefix),
                DbKeySeg::AddressSeg(source),
                DbKeySeg::AddressSeg(validator),
                DbKeySeg::StringSeg(data_1),
                DbKeySeg::StringSeg(withdraw_epoch_str),
                DbKeySeg::StringSeg(data_2),
                DbKeySeg::StringSeg(start_epoch_str),
            ] if addr == &ADDRESS
                && prefix == UNBOND_STORAGE_KEY
                && data_1 == lazy_map::DATA_SUBKEY
                && data_2 == lazy_map::DATA_SUBKEY =>
            {
                let withdraw = Epoch::parse(withdraw_epoch_str.clone()).ok()?;
                let start = Epoch::parse(start_epoch_str.clone()).ok()?;
                Some((
                    BondId {
                        source: source.clone(),
                        validator: validator.clone(),
                    },
                    start,
                    withdraw,
                ))
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Storage prefix for validator sets.
pub fn validator_sets_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&VALIDATOR_SETS_STORAGE_PREFIX.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for consensus validator set
pub fn consensus_validator_set_key() -> Key {
    validator_sets_prefix()
        .push(&CONSENSUS_VALIDATOR_SET_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for the number of consensus validators
pub fn num_consensus_validators_key() -> Key {
    validator_sets_prefix()
        .push(&NUM_CONSENSUS_VALIDATORS_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for below-capacity validator set
pub fn below_capacity_validator_set_key() -> Key {
    validator_sets_prefix()
        .push(&BELOW_CAPACITY_VALIDATOR_SET_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for the consensus validator set?
pub fn is_consensus_validator_set_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key), DbKeySeg::StringSeg(set_type), DbKeySeg::StringSeg(lazy_map), DbKeySeg::StringSeg(data), DbKeySeg::StringSeg(_epoch), DbKeySeg::StringSeg(_), DbKeySeg::StringSeg(_amount), DbKeySeg::StringSeg(_), DbKeySeg::StringSeg(_position)] if addr == &ADDRESS && key == VALIDATOR_SETS_STORAGE_PREFIX && set_type == CONSENSUS_VALIDATOR_SET_STORAGE_KEY && lazy_map == LAZY_MAP_SUB_KEY && data == lazy_map::DATA_SUBKEY)
}

/// Is storage key for the below-capacity validator set?
pub fn is_below_capacity_validator_set_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key), DbKeySeg::StringSeg(set_type), DbKeySeg::StringSeg(lazy_map), DbKeySeg::StringSeg(data), DbKeySeg::StringSeg(_epoch), DbKeySeg::StringSeg(_), DbKeySeg::StringSeg(_amount), DbKeySeg::StringSeg(_), DbKeySeg::StringSeg(_position)] if addr == &ADDRESS && key == VALIDATOR_SETS_STORAGE_PREFIX && set_type == BELOW_CAPACITY_VALIDATOR_SET_STORAGE_KEY && lazy_map == LAZY_MAP_SUB_KEY && data == lazy_map::DATA_SUBKEY)
}

/// Storage key for total deltas of all validators.
pub fn total_deltas_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&TOTAL_DELTAS_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for total deltas of all validators?
pub fn is_total_deltas_key(key: &Key) -> Option<&String> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(key),
            DbKeySeg::StringSeg(lazy_map),
            DbKeySeg::StringSeg(data),
            DbKeySeg::StringSeg(epoch),
        ] if addr == &ADDRESS
            && key == TOTAL_DELTAS_STORAGE_KEY
            && lazy_map == LAZY_MAP_SUB_KEY
            && data == lazy_map::DATA_SUBKEY =>
        {
            Some(epoch)
        }
        _ => None,
    }
}

/// Storage key for block proposer address of the previous block.
pub fn last_block_proposer_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&LAST_BLOCK_PROPOSER_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for block proposer address of the previous block?
pub fn is_last_block_proposer_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)] if addr == &ADDRESS && key == LAST_BLOCK_PROPOSER_STORAGE_KEY)
}

/// Storage key for block proposer address of the current block.
pub fn current_block_proposer_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&CURRENT_BLOCK_PROPOSER_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for block proposer address of the current block?
pub fn is_current_block_proposer_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)] if addr == &ADDRESS && key == CURRENT_BLOCK_PROPOSER_STORAGE_KEY)
}

/// Storage key for the consensus validator set rewards accumulator.
pub fn consensus_validator_rewards_accumulator_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&CONSENSUS_VALIDATOR_SET_ACCUMULATOR_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for the consensus validator set?
pub fn is_consensus_validator_set_accumulator_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(key),
        ] if addr == &ADDRESS
            && key == CONSENSUS_VALIDATOR_SET_ACCUMULATOR_STORAGE_KEY)
}

/// Get validator address from bond key
pub fn get_validator_address_from_bond(key: &Key) -> Option<Address> {
    match key.get_at(3) {
        Some(segment) => match segment {
            DbKeySeg::AddressSeg(addr) => Some(addr.clone()),
            DbKeySeg::StringSeg(_) => None,
        },
        None => None,
    }
}

/// Storage key for validator set positions
pub fn validator_set_positions_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&VALIDATOR_SET_POSITIONS_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}
