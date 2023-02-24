//! Pgf library code

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};

use crate::types::address::{Address, InternalAddress};
use crate::types::storage::Epoch;

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
    /// The epoch during which the counsil was candidated
    pub epoch: Epoch,
    /// The extra data added to the counsil
    pub data: String,
}

impl CounsilData {
    /// Checks that the data associateed with a counsil is within limit
    pub fn data_is_less_than(&self, max_characters: u64) -> bool {
        self.data.len() as u64 <= max_characters
    }
}
