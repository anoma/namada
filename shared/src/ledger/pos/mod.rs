//! Proof-of-Stake integration as a native validity predicate

pub mod vp;

pub use namada_core::ledger::storage_api;
use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
pub use namada_core::types::key::common;
pub use namada_core::types::token;
pub use namada_proof_of_stake;
pub use namada_proof_of_stake::parameters::PosParams;
pub use namada_proof_of_stake::storage::*;
pub use namada_proof_of_stake::types;
use namada_proof_of_stake::PosBase;
use rust_decimal::Decimal;
pub use vp::PosVP;

use crate::ledger::storage::{self as ledger_storage, Storage, StorageHasher};
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::Epoch;

/// Address of the PoS account implemented as a native VP
pub const ADDRESS: Address = Address::Internal(InternalAddress::PoS);

/// Address of the PoS slash pool account
pub const SLASH_POOL_ADDRESS: Address =
    Address::Internal(InternalAddress::PosSlashPool);

/// Calculate voting power in the tendermint context (which is stored as i64)
/// from the number of tokens
pub fn into_tm_voting_power(
    votes_per_token: Decimal,
    tokens: impl Into<u64>,
) -> i64 {
    let prod = decimal_mult_u64(votes_per_token, tokens.into());
    i64::try_from(prod).expect("Invalid validator voting power (i64)")
}

/// Initialize storage in the genesis block.
pub fn init_genesis_storage<'a, DB, H>(
    storage: &mut Storage<DB, H>,
    params: &'a PosParams,
    validators: impl Iterator<Item = &'a GenesisValidator> + Clone + 'a,
    current_epoch: Epoch,
) where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: StorageHasher,
{
    storage
        .init_genesis(params, validators, current_epoch)
        .expect("Initialize PoS genesis storage");
}

/// Initialize storage in the genesis block.
pub fn init_genesis_storage_new<S>(
    storage: &mut S,
    params: &PosParams,
    validators: impl Iterator<Item = GenesisValidator> + Clone,
    current_epoch: Epoch,
) where
    S: StorageRead + StorageWrite,
{
    namada_proof_of_stake::init_genesis_new(
        storage,
        params,
        validators,
        current_epoch,
    )
    .expect("Initialize PoS genesis storage");
}

/// Alias for a PoS type with the same name with concrete type parameters
pub type ValidatorConsensusKeys =
    namada_proof_of_stake::types::ValidatorConsensusKeys;

/// Alias for a PoS type with the same name with concrete type parameters
pub type ValidatorDeltas = namada_proof_of_stake::types::ValidatorDeltas;

/// Alias for a PoS type with the same name with concrete type parameters
pub type Bonds = namada_proof_of_stake::types::Bonds;

/// Alias for a PoS type with the same name with concrete type parameters
pub type Unbonds = namada_proof_of_stake::types::Unbonds;

/// Alias for a PoS type with the same name with concrete type parameters
pub type ValidatorSets = namada_proof_of_stake::types::ValidatorSets;

/// Alias for a PoS type with the same name with concrete type parameters
pub type BondId = namada_proof_of_stake::types::BondId;

/// Alias for a PoS type with the same name with concrete type parameters
pub type GenesisValidator = namada_proof_of_stake::types::GenesisValidator;
