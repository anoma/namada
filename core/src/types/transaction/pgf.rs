use std::collections::{HashSet, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::ledger::storage_api::token::Amount;
use crate::types::address::Address;
use crate::types::storage::Epoch;

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
    pub data: String
}

/// List of pgf projects for continous founding
pub type PgfProjectsUpdate = BTreeSet<PgfProject>;

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
    Deserialize
)]
pub struct PgfProject {
    /// The pgf project address
    pub address: Address,
    /// THe amoun of token to be given each epoch
    pub amount: Amount
}