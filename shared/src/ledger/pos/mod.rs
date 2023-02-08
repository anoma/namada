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
use rust_decimal::Decimal;
pub use vp::PosVP;

use crate::types::address::{self, Address, InternalAddress};
use crate::types::storage::Epoch;

/// Address of the PoS account implemented as a native VP
pub const ADDRESS: Address = Address::Internal(InternalAddress::PoS);

/// Address of the PoS slash pool account
pub const SLASH_POOL_ADDRESS: Address =
    Address::Internal(InternalAddress::PosSlashPool);

/// Address of the staking token (NAM)
pub fn staking_token_address() -> Address {
    address::nam()
}

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
pub fn init_genesis_storage<S>(
    storage: &mut S,
    params: &PosParams,
    validators: impl Iterator<Item = GenesisValidator> + Clone,
    current_epoch: Epoch,
) where
    S: StorageRead + StorageWrite,
{
    namada_proof_of_stake::init_genesis(
        storage,
        params,
        validators,
        current_epoch,
    )
    .expect("Initialize PoS genesis storage");
}

/// Alias for a PoS type with the same name with concrete type parameters
pub type BondId = namada_proof_of_stake::types::BondId;

/// Alias for a PoS type with the same name with concrete type parameters
pub type GenesisValidator = namada_proof_of_stake::types::GenesisValidator;
