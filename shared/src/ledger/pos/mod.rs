//! Proof-of-Stake integration as a native validity predicate

pub mod vp;

use std::convert::TryFrom;

pub use namada_core::ledger::storage_api;
use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
use namada_core::types::address;
pub use namada_core::types::dec::Dec;
pub use namada_core::types::key::common;
pub use namada_core::types::token;
pub use namada_proof_of_stake;
pub use namada_proof_of_stake::parameters::PosParams;
pub use namada_proof_of_stake::pos_queries::*;
pub use namada_proof_of_stake::storage::*;
pub use namada_proof_of_stake::{staking_token_address, types};
pub use vp::PosVP;

use crate::types::address::{Address, InternalAddress};
use crate::types::storage::Epoch;

/// Address of the PoS account implemented as a native VP
pub const ADDRESS: Address = address::POS;

/// Address of the PoS slash pool account
pub const SLASH_POOL_ADDRESS: Address =
    Address::Internal(InternalAddress::PosSlashPool);

/// Calculate voting power in the tendermint context (which is stored as i64)
/// from the number of tokens
pub fn into_tm_voting_power(
    votes_per_token: Dec,
    tokens: token::Amount,
) -> i64 {
    let tokens = tokens.change();
    let prod = votes_per_token * tokens;
    let res = i128::try_from(prod).expect("Failed conversion to i128");
    i64::try_from(res).expect("Invalid validator voting power (i64)")
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
