//! Pgf library code

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::{
    address::{Address, InternalAddress},
    storage::Epoch,
};

use super::storage_api::token::Amount;

/// pgf parameters
pub mod parameters;
/// pgf storage
pub mod storage;

/// The pgf internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Pgf);

/// The counsil data
#[derive(
    Clone,
    Default,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct CounsilData {
    pub epoch: Epoch,
    pub data: String,
}

impl CounsilData {
    pub fn data_is_less_than(&self, max_characters: u64) -> bool {
        return self.data.len() as u64 <= max_characters;
    }
}
