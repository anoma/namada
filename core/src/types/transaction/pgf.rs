use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::ledger::storage_api::token::Amount;
use crate::types::address::Address;
use crate::types::storage::Epoch;
use crate::types::token;

/// A tx data type to hold counsil candidate date
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct InitCounsil {
    /// The counsil enstablished address
    pub address: Address,
    /// The spending cap
    pub spending_cap: Amount,
    /// The current epoch
    pub epoch: Epoch,
    /// The arbitrary data
    pub data: String,
}

/// List of pgf projects for continous founding
pub type PgfReceipients = BTreeSet<PgfReceipient>;

/// A pgf project
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct PgfReceipient {
    /// The pgf project address
    pub address: Address,
    /// THe amoun of token to be given each epoch
    pub amount: Amount,
}

/// Definition of an active counsil
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct Counsil {
    /// The cousil address
    pub address: Address,
    /// The counsil spending cap
    pub spending_cap: token::Amount,
    /// The amount of token already spent
    pub spent_amount: token::Amount,
}

/// Definition of an a pgf candidate
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct Candidate {
    /// The address of the candidate
    pub address: Address,
    /// The candidate spending cap
    pub spending_cap: token::Amount,
    /// Arbitrary data associated with the candidate
    pub data: String,
}
