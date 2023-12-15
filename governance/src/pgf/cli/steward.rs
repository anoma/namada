use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::address::Address;
use crate::types::dec::Dec;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
/// Struct holding data about a steward commission
pub struct Commission {
    /// The steward reward distribution
    pub reward_distribution: HashMap<Address, Dec>,
}

impl TryFrom<&[u8]> for Commission {
    type Error = serde_json::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(value)
    }
}

impl Commission {
    /// Check if a steward commission is valid
    pub fn is_valid(&self) -> bool {
        let mut sum = Dec::zero();
        for percentage in self.reward_distribution.values() {
            sum = sum.add(percentage);
            if sum > Dec::one() {
                return false;
            }
        }
        true
    }
}
