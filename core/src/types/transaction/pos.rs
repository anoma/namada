//! Types used for PoS system transactions

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::address::Address;
use crate::types::dec::Dec;
use crate::types::token;

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

/// A redelegation of bonded tokens from one validator to another.
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
pub struct Redelegation {
    /// Source validator address
    pub src_validator: Address,
    /// Destination validator address
    pub dest_validator: Address,
    /// Owner (delegator) of the bonds to be redelegate
    pub owner: Address,
    /// The amount of tokens
    pub amount: token::Amount,
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
