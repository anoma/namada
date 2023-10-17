use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::address::Address;
use crate::types::dec::Dec;

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum PgfError {
    #[error("Invalid pgf update commission transaction.")]
    InvalidPgfCommission,
}

/// A tx data type to hold proposal data
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct UpdateStewardCommission {
    /// The pgf steward address
    pub steward: Address,
    /// The new commission distribution
    pub commission: HashMap<Address, Dec>,
}
