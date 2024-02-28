use std::collections::HashMap;

use namada_core::address::Address;
use namada_core::dec::Dec;
use serde::{Deserialize, Serialize};

use crate::pgf::REWARD_DISTRIBUTION_LIMIT;

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
        if self.reward_distribution.len() as u64 > REWARD_DISTRIBUTION_LIMIT {
            return false;
        }

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
