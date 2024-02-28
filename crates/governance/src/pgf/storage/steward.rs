use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::address::Address;
use namada_core::dec::Dec;

use crate::pgf::REWARD_DISTRIBUTION_LIMIT;

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

    /// Check if reward distribution is valid
    pub fn is_valid_reward_distribution(&self) -> bool {
        if self.reward_distribution.len() as u64 > REWARD_DISTRIBUTION_LIMIT {
            return false;
        }

        let mut sum = Dec::zero();
        for percentage in self.reward_distribution.values().cloned() {
            if percentage < Dec::zero() || percentage > Dec::one() {
                return false;
            }
            sum += percentage;
        }

        sum <= Dec::one()
    }
}
