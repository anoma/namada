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