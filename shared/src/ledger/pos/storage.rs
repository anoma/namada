//! Proof-of-Stake storage keys and storage integration via [`PosBase`] trait.

use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::types::{
    Epoch, RewardsProducts, ValidatorStates, VoteInfo,
};
use namada_proof_of_stake::{types, PosBase};

use super::{
    BondId, Bonds, CommissionRates, TotalDeltas, ValidatorConsensusKeys,
    ValidatorDeltas, ValidatorSets, ADDRESS,
};
use crate::ledger::storage::types::{decode, encode};
use crate::ledger::storage::{self, Storage, StorageHasher};
use crate::types::address::Address;
use crate::types::storage::{DbKeySeg, Key, KeySeg};
use crate::types::{key, token};

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
const VALIDATOR_SET_STORAGE_KEY: &str = "validator_set";
const VALIDATOR_SET_STORAGE_PREFIX: &str = "validator_set";
const CONSENSUS_VALIDATOR_SET_STORAGE_PREFIX: &str = "consensus";
const CONSENSUS_VALIDATOR_SET_STORAGE_KEY: &str = "set";
const CONSENSUS_VALIDATOR_SET_ACCUMULATOR_STORAGE_KEY: &str =
    "reward_accumulator";
const BELOW_CAPACITY_VALIDATOR_SET_STORAGE_KEY: &str = "below_capacity";
const BELOW_THRESHOLD_VALIDATOR_SET_STORAGE_KEY: &str = "below_threshold";
const TOTAL_DELTAS_STORAGE_KEY: &str = "total_deltas";
const LAST_CONSENSUS_VOTES_STORAGE_KEY: &str = "last_consensus_votes";

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
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)]
            if addr == &ADDRESS && key == PARAMS_STORAGE_KEY =>
        {
            true
        }
        _ => false,
    }
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

/// Storage key for validator's state.
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
        ] if addr == &ADDRESS
            && prefix == VALIDATOR_STORAGE_PREFIX
            && key == VALIDATOR_DELTAS_STORAGE_KEY =>
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

/// Is storage key for validator's slashes?
pub fn is_validator_slashes_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(validator),
        ] if addr == &ADDRESS && prefix == SLASHES_PREFIX => Some(validator),
        _ => None,
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

/// Is storage key for a bond?
pub fn is_bond_key(key: &Key) -> Option<BondId> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(source),
            DbKeySeg::AddressSeg(validator),
        ] if addr == &ADDRESS && prefix == BOND_STORAGE_KEY => Some(BondId {
            source: source.clone(),
            validator: validator.clone(),
        }),
        _ => None,
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

/// Is storage key for a unbond?
pub fn is_unbond_key(key: &Key) -> Option<BondId> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::AddressSeg(source),
            DbKeySeg::AddressSeg(validator),
        ] if addr == &ADDRESS && prefix == UNBOND_STORAGE_KEY => Some(BondId {
            source: source.clone(),
            validator: validator.clone(),
        }),
        _ => None,
    }
}

/// Storage key for validator set (active and inactive).
pub fn validator_set_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&VALIDATOR_SET_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for a validator set?
pub fn is_validator_set_key(key: &Key) -> bool {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)]
            if addr == &ADDRESS && key == VALIDATOR_SET_STORAGE_KEY =>
        {
            true
        }
        _ => false,
    }
}

/// Storage key prefix for validator sets.
pub fn validator_set_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&VALIDATOR_SET_STORAGE_PREFIX.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key prefix for the consensus validator set.
pub fn consensus_validator_set_prefix() -> Key {
    validator_set_prefix()
        .push(&CONSENSUS_VALIDATOR_SET_STORAGE_PREFIX.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Storage key for consensus validator set.
pub fn consensus_validator_set_key() -> Key {
    consensus_validator_set_prefix()
        .push(&CONSENSUS_VALIDATOR_SET_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for the consensus validator set?
pub fn is_consensus_validator_set_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(key),
            DbKeySeg::StringSeg(set),
            DbKeySeg::StringSeg(field),
        ] if addr == &ADDRESS
            && key == VALIDATOR_SET_STORAGE_KEY
            && set == CONSENSUS_VALIDATOR_SET_STORAGE_PREFIX
            && field == CONSENSUS_VALIDATOR_SET_STORAGE_KEY =>
        {
            true
        }
        _ => false,
    }
}

/// Storage key for the consensus validator set rewards accumulator.
pub fn consensus_validator_set_accumulator_key() -> Key {
    consensus_validator_set_prefix()
        .push(&CONSENSUS_VALIDATOR_SET_ACCUMULATOR_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for the consensus validator set?
pub fn is_consensus_validator_set_accumulator_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(key),
            DbKeySeg::StringSeg(set),
            DbKeySeg::StringSeg(field),
        ] if addr == &ADDRESS
            && key == VALIDATOR_SET_STORAGE_PREFIX
            && set == CONSENSUS_VALIDATOR_SET_STORAGE_PREFIX
            && field == CONSENSUS_VALIDATOR_SET_ACCUMULATOR_STORAGE_KEY =>
        {
            true
        }
        _ => false,
    }
}

/// Storage key for the below capacity validator set
pub fn below_capacity_validator_set_key() -> Key {
    validator_set_prefix()
        .push(&BELOW_CAPACITY_VALIDATOR_SET_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for the below capacity validator set?
pub fn is_below_capacity_validator_set_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(key),
            DbKeySeg::StringSeg(set),
        ] if addr == &ADDRESS
            && key == VALIDATOR_SET_STORAGE_PREFIX
            && set == BELOW_CAPACITY_VALIDATOR_SET_STORAGE_KEY =>
        {
            true
        }
        _ => false,
    }
}

/// Storage key for the below threshold validator set
pub fn below_threshold_validator_set_key() -> Key {
    validator_set_prefix()
        .push(&BELOW_THRESHOLD_VALIDATOR_SET_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for the below threshold validator set?
pub fn is_below_threshold_validator_set_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(key),
            DbKeySeg::StringSeg(set),
        ] if addr == &ADDRESS
            && key == VALIDATOR_SET_STORAGE_PREFIX
            && set == BELOW_THRESHOLD_VALIDATOR_SET_STORAGE_KEY =>
        {
            true
        }
        _ => false,
    }
}

/// Storage key for total deltas of all validators.
pub fn total_deltas_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&TOTAL_DELTAS_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for total deltas of all validators?
pub fn is_total_deltas_key(key: &Key) -> bool {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)]
            if addr == &ADDRESS && key == TOTAL_DELTAS_STORAGE_KEY =>
        {
            true
        }
        _ => false,
    }
}

/// Storage key for consensus votes of the previous block.
pub fn last_consensus_votes_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&LAST_CONSENSUS_VOTES_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for consensus votes of the previous block?
pub fn is_last_consensus_votes_key(key: &Key) -> bool {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)]
            if addr == &ADDRESS && key == LAST_CONSENSUS_VOTES_STORAGE_KEY =>
        {
            true
        }
        _ => false,
    }
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

impl<D, H> PosBase for Storage<D, H>
where
    D: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    type Address = Address;
    type PublicKey = key::common::PublicKey;
    type TokenAmount = token::Amount;
    type TokenChange = token::Change;

    const POS_ADDRESS: Self::Address = super::ADDRESS;
    const POS_SLASH_POOL_ADDRESS: Self::Address = super::SLASH_POOL_ADDRESS;

    fn staking_token_address() -> Self::Address {
        super::staking_token_address()
    }

    fn read_pos_address(&self) -> Self::Address {
        Self::POS_ADDRESS
    }

    fn read_pos_params(&self) -> PosParams {
        let (value, _gas) = self.read(&params_key()).unwrap();
        decode(value.unwrap()).unwrap()
    }

    fn read_validator_address_raw_hash(
        &self,
        raw_hash: impl AsRef<str>,
    ) -> Option<Self::Address> {
        let (value, _gas) = self
            .read(&validator_address_raw_hash_key(raw_hash))
            .unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_validator_consensus_key(
        &self,
        key: &Self::Address,
    ) -> Option<ValidatorConsensusKeys> {
        let (value, _gas) =
            self.read(&validator_consensus_key_key(key)).unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_validator_state(
        &self,
        key: &Self::Address,
    ) -> Option<ValidatorStates> {
        let (value, _gas) = self.read(&validator_state_key(key)).unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_validator_deltas(
        &self,
        key: &Self::Address,
    ) -> Option<types::ValidatorDeltas<Self::TokenChange>> {
        let (value, _gas) = self.read(&validator_deltas_key(key)).unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_last_block_consensus_votes(&self) -> Option<Vec<VoteInfo>> {
        let (value, _gas) = self.read(&last_consensus_votes_key()).unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_validator_slashes(&self, key: &Self::Address) -> types::Slashes {
        let (value, _gas) = self.read(&validator_slashes_key(key)).unwrap();
        value
            .map(|value| decode(value).unwrap())
            .unwrap_or_default()
    }

    fn read_validator_commission_rate(
        &self,
        key: &Self::Address,
    ) -> CommissionRates {
        let (value, _gas) =
            self.read(&validator_commission_rate_key(key)).unwrap();
        decode(value.unwrap()).unwrap()
    }

    fn read_validator_max_commission_rate_change(
        &self,
        key: &Self::Address,
    ) -> rust_decimal::Decimal {
        let (value, _gas) =
            self.read(&validator_commission_rate_key(key)).unwrap();
        decode(value.unwrap()).unwrap()
    }

    fn read_validator_rewards_products(
        &self,
        key: &Self::Address,
    ) -> Option<RewardsProducts> {
        let (value, _gas) =
            self.read(&validator_self_rewards_product_key(key)).unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_validator_delegation_rewards_products(
        &self,
        key: &Self::Address,
    ) -> Option<RewardsProducts> {
        let (value, _gas) = self
            .read(&validator_delegation_rewards_product_key(key))
            .unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_validator_last_known_product_epoch(
        &self,
        key: &Self::Address,
    ) -> Epoch {
        let (value, _gas) = self
            .read(&validator_delegation_rewards_product_key(key))
            .unwrap();
        decode(value.unwrap()).unwrap()
    }

    fn read_consensus_validator_rewards_accumulator(
        &self,
    ) -> Option<std::collections::HashMap<Self::Address, rust_decimal::Decimal>>
    {
        let (value, _gas) = self
            .read(&consensus_validator_set_accumulator_key())
            .unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_validator_set(&self) -> ValidatorSets {
        let (value, _gas) = self.read(&validator_set_key()).unwrap();
        decode(value.unwrap()).unwrap()
    }

    fn read_total_deltas(&self) -> TotalDeltas {
        let (value, _gas) = self.read(&total_deltas_key()).unwrap();
        decode(value.unwrap()).unwrap()
    }

    fn write_pos_params(&mut self, params: &PosParams) {
        self.write(&params_key(), encode(params)).unwrap();
    }

    fn write_validator_address_raw_hash(
        &mut self,
        address: &Self::Address,
        consensus_key: &Self::PublicKey,
    ) {
        let raw_hash = key::tm_consensus_key_raw_hash(consensus_key);
        self.write(&validator_address_raw_hash_key(raw_hash), encode(address))
            .unwrap();
    }

    fn write_validator_commission_rate(
        &mut self,
        key: &Self::Address,
        value: &CommissionRates,
    ) {
        self.write(&validator_commission_rate_key(key), encode(value))
            .unwrap();
    }

    fn write_validator_max_commission_rate_change(
        &mut self,
        key: &Self::Address,
        value: &rust_decimal::Decimal,
    ) {
        self.write(
            &validator_max_commission_rate_change_key(key),
            encode(value),
        )
        .unwrap();
    }

    fn write_validator_rewards_products(
        &mut self,
        key: &Self::Address,
        value: &RewardsProducts,
    ) {
        self.write(&validator_self_rewards_product_key(key), encode(value))
            .unwrap();
    }

    fn write_validator_delegation_rewards_products(
        &mut self,
        key: &Self::Address,
        value: &RewardsProducts,
    ) {
        self.write(
            &validator_delegation_rewards_product_key(key),
            encode(value),
        )
        .unwrap();
    }

    fn write_validator_last_known_product_epoch(
        &mut self,
        key: &Self::Address,
        value: &Epoch,
    ) {
        self.write(&validator_last_known_product_epoch_key(key), encode(value))
            .unwrap();
    }

    fn write_consensus_validator_rewards_accumulator(
        &mut self,
        value: &std::collections::HashMap<Self::Address, rust_decimal::Decimal>,
    ) {
        self.write(&consensus_validator_set_accumulator_key(), encode(value))
            .unwrap();
    }

    fn write_validator_consensus_key(
        &mut self,
        key: &Self::Address,
        value: &ValidatorConsensusKeys,
    ) {
        self.write(&validator_consensus_key_key(key), encode(value))
            .unwrap();
    }

    fn write_validator_state(
        &mut self,
        key: &Self::Address,
        value: &ValidatorStates,
    ) {
        self.write(&validator_state_key(key), encode(value))
            .unwrap();
    }

    fn write_validator_deltas(
        &mut self,
        key: &Self::Address,
        value: &ValidatorDeltas,
    ) {
        self.write(&validator_deltas_key(key), encode(value))
            .unwrap();
    }

    fn write_validator_slash(
        &mut self,
        validator: &Self::Address,
        value: types::Slash,
    ) {
        let mut slashes = self.read_validator_slashes(validator);
        slashes.push(value);
        self.write(&validator_slashes_key(validator), encode(&slashes))
            .unwrap();
    }

    fn write_bond(&mut self, key: &BondId, value: &Bonds) {
        self.write(&bond_key(key), encode(value)).unwrap();
    }

    fn write_validator_set(&mut self, value: &ValidatorSets) {
        self.write(&validator_set_key(), encode(value)).unwrap();
    }

    fn write_total_deltas(&mut self, value: &TotalDeltas) {
        self.write(&total_deltas_key(), encode(value)).unwrap();
    }

    fn write_last_block_consensus_votes(&mut self, value: &Vec<VoteInfo>) {
        self.write(&last_consensus_votes_key(), encode(value))
            .unwrap();
    }

    fn credit_tokens(
        &mut self,
        token: &Self::Address,
        target: &Self::Address,
        amount: Self::TokenAmount,
    ) {
        let key = token::balance_key(token, target);
        let new_balance = match self
            .read(&key)
            .expect("Unable to read token balance for PoS system")
        {
            (Some(balance), _gas) => {
                let balance: Self::TokenAmount =
                    decode(balance).unwrap_or_default();
                balance + amount
            }
            _ => amount,
        };
        self.write(&key, encode(&new_balance))
            .expect("Unable to write token balance for PoS system");
    }

    fn transfer(
        &mut self,
        token: &Self::Address,
        amount: Self::TokenAmount,
        src: &Self::Address,
        dest: &Self::Address,
    ) {
        let src_key = token::balance_key(token, src);
        let dest_key = token::balance_key(token, dest);
        if let (Some(src_balance), _gas) = self
            .read(&src_key)
            .expect("Unable to read token balance for PoS system")
        {
            let mut src_balance: Self::TokenAmount =
                decode(src_balance).unwrap_or_default();
            if src_balance < amount {
                tracing::error!(
                    "PoS system transfer error, the source doesn't have \
                     sufficient balance. It has {}, but {} is required",
                    src_balance,
                    amount
                );
                return;
            }
            src_balance.spend(&amount);
            let (dest_balance, _gas) = self.read(&dest_key).unwrap_or_default();
            let mut dest_balance: Self::TokenAmount = dest_balance
                .and_then(|b| decode(b).ok())
                .unwrap_or_default();
            dest_balance.receive(&amount);
            self.write(&src_key, encode(&src_balance))
                .expect("Unable to write token balance for PoS system");
            self.write(&dest_key, encode(&dest_balance))
                .expect("Unable to write token balance for PoS system");
        } else {
            tracing::error!(
                "PoS system transfer error, the source has no balance"
            );
        }
    }
}
