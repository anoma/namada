use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::types::address::Address;
use crate::types::dec::Dec;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, PartialEq)]
/// Struct holding data about a pgf steward
pub struct StewardDetail {
    /// The steward address
    pub address: Address,
    /// The steward reward distribution
    pub reward_distribution: HashMap<Address, Dec>,
}

impl StewardDetail {
    /// Create an initial steward configuration
    pub fn base(address: Address) -> Self {
        Self {
            address: address.to_owned(),
            reward_distribution: HashMap::from_iter([(address, Dec::one())]),
        }
    }
}
