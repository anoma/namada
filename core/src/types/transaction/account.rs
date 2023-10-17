use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::address::Address;
use crate::types::hash::Hash;
use crate::types::key::common;

/// A tx data type to initialize a new established account
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
pub struct InitAccount {
    /// Public keys to be written into the account's storage. This can be used
    /// for signature verification of transactions for the newly created
    /// account.
    pub public_keys: Vec<common::PublicKey>,
    /// The VP code hash
    pub vp_code_hash: Hash,
    /// The account signature threshold
    pub threshold: u8,
}

/// A tx data type to update an account's validity predicate
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
pub struct UpdateAccount {
    /// An address of the account
    pub addr: Address,
    /// The new VP code hash
    pub vp_code_hash: Option<Hash>,
    /// Public keys to be written into the account's storage. This can be used
    /// for signature verification of transactions for the newly created
    /// account.
    pub public_keys: Vec<common::PublicKey>,
    /// The account signature threshold
    pub threshold: Option<u8>,
}
