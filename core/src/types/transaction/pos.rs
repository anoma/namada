//! Types used for PoS system transactions

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::address::Address;
use crate::types::dec::Dec;
use crate::types::hash::Hash;
use crate::types::key::{common, secp256k1};
use crate::types::token;

/// A tx data type to initialize a new validator account.
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct InitValidator {
    /// Public key to be written into the account's storage. This can be used
    /// for signature verification of transactions for the newly created
    /// account.
    pub account_keys: Vec<common::PublicKey>,
    /// The minimum number of signatures needed
    pub threshold: u8,
    /// A key to be used for signing blocks and votes on blocks.
    pub consensus_key: common::PublicKey,
    /// An Eth bridge governance public key
    pub eth_cold_key: secp256k1::PublicKey,
    /// An Eth bridge hot signing public key used for validator set updates and
    /// cross-chain transactions
    pub eth_hot_key: secp256k1::PublicKey,
    /// Public key used to sign protocol transactions
    pub protocol_key: common::PublicKey,
    /// Serialization of the public session key used in the DKG
    pub dkg_key: crate::types::key::dkg_session_keys::DkgPublicKey,
    /// The initial commission rate charged for delegation rewards
    pub commission_rate: Dec,
    /// The maximum change allowed per epoch to the commission rate. This is
    /// immutable once set here.
    pub max_commission_rate_change: Dec,
    /// The VP code for validator account
    pub validator_vp_code_hash: Hash,
}

/// A bond is a validator's self-bond or a delegation from non-validator to a
/// validator.
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Hash,
    Eq,
    Serialize,
    Deserialize,
)]
pub struct Bond {
    /// Validator address
    pub validator: Address,
    /// The amount of tokens
    pub amount: token::Amount,
    /// Source address for delegations. For self-bonds, the validator is
    /// also the source.
    pub source: Option<Address>,
}

/// An unbond of a bond.
pub type Unbond = Bond;

/// A withdrawal of an unbond.
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Hash,
    Eq,
    Serialize,
    Deserialize,
)]
pub struct Withdraw {
    /// Validator address
    pub validator: Address,
    /// Source address for withdrawing from delegations. For withdrawing
    /// from self-bonds, the validator is also the source
    pub source: Option<Address>,
}

/// A change to the validator commission rate.
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Hash,
    Eq,
    Serialize,
    Deserialize,
)]
pub struct CommissionChange {
    /// Validator address
    pub validator: Address,
    /// The new commission rate
    pub new_rate: Dec,
}
