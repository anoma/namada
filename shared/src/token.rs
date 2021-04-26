//! A basic fungible token

use borsh::{BorshDeserialize, BorshSerialize};

use crate::types::{Address, Key, KeySeg};

/// Amount in micro units. For different granularity another representation
/// might be more appropriate.
#[derive(
    Clone,
    Copy,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
)]
pub struct Amount {
    micro: u64,
}

pub type Change = i128;

impl Default for Amount {
    fn default() -> Self {
        Self { micro: 0 }
    }
}

impl Amount {
    pub fn change(&self) -> Change {
        self.micro as Change
    }

    pub fn spend(&mut self, amount: &Amount) {
        self.micro -= amount.micro
    }

    pub fn receive(&mut self, amount: &Amount) {
        self.micro += amount.micro
    }

    pub fn whole(amount: u64) -> Self {
        Self {
            micro: amount * 1_000_000,
        }
    }
}

impl From<u64> for Amount {
    fn from(micro: u64) -> Self {
        Self { micro }
    }
}

/// Obtain a key at which a user's balance is stored
pub fn balance_key(token_addr: &Address, owner: &Address) -> Key {
    Key::from(token_addr.to_db_key())
        .push(&"balance".to_owned())
        .expect("Cannot obtain a balance key")
        .push(&owner.to_db_key())
        .expect("Cannot obtain a balance key")
}
