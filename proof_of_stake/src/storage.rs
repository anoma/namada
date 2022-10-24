//! Proof-of-Stake storage keys and storage integration via [`PosBase`] trait.

use namada_core::ledger::storage::types::{decode, encode};
use namada_core::ledger::storage::{self, Storage, StorageHasher};
use namada_core::types::address::Address;
use namada_core::types::storage::{DbKeySeg, Epoch, Key, KeySeg};
use namada_core::types::{key, token};
use rust_decimal::Decimal;

use super::ADDRESS;
use crate::parameters::PosParams;
pub use crate::types::*;
use crate::{types, PosBase, PosReadOnly};

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
const TOTAL_DELTAS_STORAGE_KEY: &str = "total_deltas";
const LAST_BLOCK_PROPOSER_STORAGE_KEY: &str = "last_block_proposer";
const CURRENT_BLOCK_PROPOSER_STORAGE_KEY: &str = "current_block_proposer";

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
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)] if addr == &ADDRESS && key == VALIDATOR_SET_STORAGE_KEY)
}

/// Storage key for total deltas of all validators.
pub fn total_deltas_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&TOTAL_DELTAS_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for total deltas of all validators?
pub fn is_total_deltas_key(key: &Key) -> bool {
    matches!(&key.segments[..],
                [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)]
                    if addr == &ADDRESS && key == TOTAL_DELTAS_STORAGE_KEY)
}

/// Storage key for block proposer address of the previous block.
pub fn last_block_proposer_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&LAST_BLOCK_PROPOSER_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for block proposer address of the previous block?
pub fn is_last_block_proposer_key(key: &Key) -> bool {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)]
            if addr == &ADDRESS && key == LAST_BLOCK_PROPOSER_STORAGE_KEY =>
        {
            true
        }
        _ => false,
    }
}

/// Storage key for block proposer address of the current block.
pub fn current_block_proposer_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&CURRENT_BLOCK_PROPOSER_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Is storage key for block proposer address of the current block?
pub fn is_current_block_proposer_key(key: &Key) -> bool {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)]
            if addr == &ADDRESS
                && key == CURRENT_BLOCK_PROPOSER_STORAGE_KEY =>
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
    const POS_ADDRESS: Address = super::ADDRESS;
    const POS_SLASH_POOL_ADDRESS: Address = super::SLASH_POOL_ADDRESS;

    fn staking_token_address(&self) -> Address {
        self.native_token.clone()
    }

    fn read_pos_params(&self) -> PosParams {
        let (value, _gas) = self.read(&params_key()).unwrap();
        decode(value.unwrap()).unwrap()
    }

    fn read_validator_address_raw_hash(
        &self,
        raw_hash: impl AsRef<str>,
    ) -> Option<Address> {
        let (value, _gas) = self
            .read(&validator_address_raw_hash_key(raw_hash))
            .unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_validator_consensus_key(
        &self,
        key: &Address,
    ) -> Option<ValidatorConsensusKeys> {
        let (value, _gas) =
            self.read(&validator_consensus_key_key(key)).unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_validator_state(&self, key: &Address) -> Option<ValidatorStates> {
        let (value, _gas) = self.read(&validator_state_key(key)).unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_validator_deltas(
        &self,
        key: &Address,
    ) -> Option<types::ValidatorDeltas> {
        let (value, _gas) = self.read(&validator_deltas_key(key)).unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_last_block_proposer_address(&self) -> Option<Address> {
        let (value, _gas) = self.read(&last_block_proposer_key()).unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_current_block_proposer_address(&self) -> Option<Address> {
        let (value, _gas) = self.read(&current_block_proposer_key()).unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_validator_slashes(&self, key: &Address) -> types::Slashes {
        let (value, _gas) = self.read(&validator_slashes_key(key)).unwrap();
        value
            .map(|value| decode(value).unwrap())
            .unwrap_or_default()
    }

    fn read_validator_commission_rate(&self, key: &Address) -> CommissionRates {
        let (value, _gas) =
            self.read(&validator_commission_rate_key(key)).unwrap();
        decode(value.unwrap()).unwrap()
    }

    fn read_validator_max_commission_rate_change(
        &self,
        key: &Address,
    ) -> Decimal {
        let (value, _gas) = self
            .read(&validator_max_commission_rate_change_key(key))
            .unwrap();
        decode(value.unwrap()).unwrap()
    }

    fn read_validator_rewards_products(
        &self,
        key: &Address,
    ) -> Option<RewardsProducts> {
        let (value, _gas) =
            self.read(&validator_self_rewards_product_key(key)).unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_validator_delegation_rewards_products(
        &self,
        key: &Address,
    ) -> Option<RewardsProducts> {
        let (value, _gas) = self
            .read(&validator_delegation_rewards_product_key(key))
            .unwrap();
        value.map(|value| decode(value).unwrap())
    }

    fn read_validator_last_known_product_epoch(&self, key: &Address) -> Epoch {
        let (value, _gas) = self
            .read(&validator_delegation_rewards_product_key(key))
            .unwrap();
        decode(value.unwrap()).unwrap()
    }

    fn read_consensus_validator_rewards_accumulator(
        &self,
    ) -> Option<std::collections::HashMap<Address, Decimal>> {
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
        address: &Address,
        consensus_key: &namada_core::types::key::common::PublicKey,
    ) {
        let raw_hash = key::tm_consensus_key_raw_hash(consensus_key);
        self.write(&validator_address_raw_hash_key(raw_hash), encode(address))
            .unwrap();
    }

    fn write_validator_commission_rate(
        &mut self,
        key: &Address,
        value: &CommissionRates,
    ) {
        self.write(&validator_commission_rate_key(key), encode(value))
            .unwrap();
    }

    fn write_validator_max_commission_rate_change(
        &mut self,
        key: &Address,
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
        key: &Address,
        value: &RewardsProducts,
    ) {
        self.write(&validator_self_rewards_product_key(key), encode(value))
            .unwrap();
    }

    fn write_validator_delegation_rewards_products(
        &mut self,
        key: &Address,
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
        key: &Address,
        value: &Epoch,
    ) {
        self.write(&validator_last_known_product_epoch_key(key), encode(value))
            .unwrap();
    }

    fn write_consensus_validator_rewards_accumulator(
        &mut self,
        value: &std::collections::HashMap<Address, rust_decimal::Decimal>,
    ) {
        self.write(&consensus_validator_set_accumulator_key(), encode(value))
            .unwrap();
    }

    fn write_validator_consensus_key(
        &mut self,
        key: &Address,
        value: &ValidatorConsensusKeys,
    ) {
        self.write(&validator_consensus_key_key(key), encode(value))
            .unwrap();
    }

    fn write_validator_state(
        &mut self,
        key: &Address,
        value: &ValidatorStates,
    ) {
        self.write(&validator_state_key(key), encode(value))
            .unwrap();
    }

    fn write_validator_deltas(
        &mut self,
        key: &Address,
        value: &ValidatorDeltas,
    ) {
        self.write(&validator_deltas_key(key), encode(value))
            .unwrap();
    }

    fn write_validator_slash(
        &mut self,
        validator: &Address,
        value: types::Slash,
    ) {
        let mut slashes = PosBase::read_validator_slashes(self, validator);
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

    fn write_last_block_proposer_address(&mut self, value: &Address) {
        self.write(&last_block_proposer_key(), encode(value))
            .unwrap();
    }

    fn write_current_block_proposer_address(&mut self, value: &Self::Address) {
        self.write(&current_block_proposer_key(), encode(value))
            .unwrap();
    }

    fn credit_tokens(
        &mut self,
        token: &Address,
        target: &Address,
        amount: namada_core::types::token::Amount,
    ) {
        let key = token::balance_key(token, target);
        let new_balance = match self
            .read(&key)
            .expect("Unable to read token balance for PoS system")
        {
            (Some(balance), _gas) => {
                let balance: namada_core::types::token::Amount =
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
        token: &Address,
        amount: namada_core::types::token::Amount,
        src: &Address,
        dest: &Address,
    ) {
        let src_key = token::balance_key(token, src);
        let dest_key = token::balance_key(token, dest);
        if let (Some(src_balance), _gas) = self
            .read(&src_key)
            .expect("Unable to read token balance for PoS system")
        {
            let mut src_balance: namada_core::types::token::Amount =
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
            let mut dest_balance: namada_core::types::token::Amount =
                dest_balance
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

/// Implement `PosReadOnly` for a type that implements
/// [`trait@namada_core::ledger::storage_api::StorageRead`].
///
/// Excuse the horrible syntax - we haven't found a better way to use this
/// for native_vp `CtxPreStorageRead`/`CtxPostStorageRead`, which have
/// generics and explicit lifetimes.
///
/// # Examples
///
/// ```ignore
/// impl_pos_read_only! { impl PosReadOnly for X }
/// ```
#[macro_export]
macro_rules! impl_pos_read_only {
    (
        // Matches anything, so that we can use lifetimes and generic types.
        // This expects `impl(<.*>)? PoSReadOnly for $ty(<.*>)?`.
        $( $any:tt )* )
    => {
        $( $any )*
        {
            const POS_ADDRESS: namada_core::types::address::Address = $crate::ADDRESS;

            fn staking_token_address(&self) -> namada_core::types::address::Address {
                namada_core::ledger::storage_api::StorageRead::get_native_token(self)
                    .expect("Native token must be available")
            }

            fn read_pos_params(&self) -> namada_core::ledger::storage_api::Result<PosParams> {
                let value = namada_core::ledger::storage_api::StorageRead::read_bytes(self, &params_key())?.unwrap();
                Ok(namada_core::ledger::storage::types::decode(value).unwrap())
            }

            fn read_validator_consensus_key(
                &self,
                key: &namada_core::types::address::Address,
            ) -> namada_core::ledger::storage_api::Result<Option<ValidatorConsensusKeys>> {
                let value =
                    namada_core::ledger::storage_api::StorageRead::read_bytes(self, &validator_consensus_key_key(key))?;
                Ok(value.map(|value| namada_core::ledger::storage::types::decode(value).unwrap()))
            }

            fn read_validator_commission_rate(
                &self,
                key: &namada_core::types::address::Address,
            ) -> namada_core::ledger::storage_api::Result<Option<CommissionRates>> {
                let value =
                    namada_core::ledger::storage_api::StorageRead::read_bytes(self, &validator_commission_rate_key(key))?;
                Ok(value.map(|value| namada_core::ledger::storage::types::decode(value).unwrap()))
            }

            fn read_validator_max_commission_rate_change(
                &self,
                key: &namada_core::types::address::Address,
            ) -> namada_core::ledger::storage_api::Result<Option<Decimal>> {
                let value =
                    namada_core::ledger::storage_api::StorageRead::read_bytes(self, &validator_max_commission_rate_change_key(key))?;
                Ok(value.map(|value| namada_core::ledger::storage::types::decode(value).unwrap()))
            }

            fn read_validator_state(
                &self,
                key: &namada_core::types::address::Address,
            ) -> namada_core::ledger::storage_api::Result<Option<ValidatorStates>> {
                let value = namada_core::ledger::storage_api::StorageRead::read_bytes(self, &validator_state_key(key))?;
                Ok(value.map(|value| namada_core::ledger::storage::types::decode(value).unwrap()))
            }

            fn read_validator_deltas(
                &self,
                key: &namada_core::types::address::Address,
            ) -> namada_core::ledger::storage_api::Result<Option<ValidatorDeltas>> {
                let value =
                    namada_core::ledger::storage_api::StorageRead::read_bytes(self, &validator_deltas_key(key))?;
                Ok(value.map(|value| namada_core::ledger::storage::types::decode(value).unwrap()))
            }

            fn read_validator_slashes(
                &self,
                key: &namada_core::types::address::Address,
            ) -> namada_core::ledger::storage_api::Result<Vec<types::Slash>> {
                let value = namada_core::ledger::storage_api::StorageRead::read_bytes(self, &validator_slashes_key(key))?;
                Ok(value
                    .map(|value| namada_core::ledger::storage::types::decode(value).unwrap())
                    .unwrap_or_default())
            }

            fn read_bond(
                &self,
                key: &BondId,
            ) -> namada_core::ledger::storage_api::Result<Option<Bonds>> {
                let value = namada_core::ledger::storage_api::StorageRead::read_bytes(self, &bond_key(key))?;
                Ok(value.map(|value| namada_core::ledger::storage::types::decode(value).unwrap()))
            }

            fn read_unbond(
                &self,
                key: &BondId,
            ) -> namada_core::ledger::storage_api::Result<Option<Unbonds>> {
                let value = namada_core::ledger::storage_api::StorageRead::read_bytes(self, &unbond_key(key))?;
                Ok(value.map(|value| namada_core::ledger::storage::types::decode(value).unwrap()))
            }

            fn read_validator_set(
                &self,
            ) -> namada_core::ledger::storage_api::Result<ValidatorSets> {
                let value =
                    namada_core::ledger::storage_api::StorageRead::read_bytes(self, &validator_set_key())?.unwrap();
                Ok(namada_core::ledger::storage::types::decode(value).unwrap())
            }

            fn read_total_deltas(
                &self,
            ) -> namada_core::ledger::storage_api::Result<TotalDeltas> {
                let value =
                    namada_core::ledger::storage_api::StorageRead::read_bytes(self, &total_deltas_key())?.unwrap();
                Ok(namada_core::ledger::storage::types::decode(value).unwrap())
            }
        }
    }
}

impl_pos_read_only! {
    impl<DB, H> PosReadOnly for Storage<DB, H>
        where
            DB: storage::DB + for<'iter> storage::DBIter<'iter> +'static,
            H: StorageHasher +'static,
}
