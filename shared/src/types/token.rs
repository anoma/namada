//! A basic fungible token

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::address::Address;
use crate::types::key::ed25519::{Keypair, SignedTxData};
use crate::types::storage::{DbKeySeg, Key, KeySeg};

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
    Hash,
    Serialize,
    Deserialize,
)]
pub struct Amount {
    micro: u64,
}

/// A change in tokens amount
pub type Change = i128;

impl Default for Amount {
    fn default() -> Self {
        Self { micro: 0 }
    }
}

impl Amount {
    /// Get the amount as a [`Change`]
    pub fn change(&self) -> Change {
        self.micro as Change
    }

    /// Spend a given amount
    pub fn spend(&mut self, amount: &Amount) {
        self.micro -= amount.micro
    }

    /// Receive a given amount
    pub fn receive(&mut self, amount: &Amount) {
        self.micro += amount.micro
    }

    /// Create a new amount from whole number of tokens
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

impl From<f64> for Amount {
    fn from(decimal: f64) -> Self {
        Self {
            micro: (decimal * 1_000_000.0).round() as u64,
        }
    }
}

const BALANCE_STORAGE_KEY: &str = "balance";

/// Obtain a storage key for user's balance.
pub fn balance_key(token_addr: &Address, owner: &Address) -> Key {
    Key::from(token_addr.to_db_key())
        .push(&BALANCE_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&owner.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Check if the given storage key is balance key for the given token. If it is,
/// returns the owner.
pub fn is_balance_key<'a>(
    token_addr: &Address,
    key: &'a Key,
) -> Option<&'a Address> {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key), DbKeySeg::AddressSeg(owner)]
            if key == BALANCE_STORAGE_KEY && addr == token_addr =>
        {
            Some(owner)
        }
        _ => None,
    }
}

/// Check if the given storage key is balance key for unspecified token. If it
/// is, returns the owner.
pub fn is_any_token_balance_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(_), DbKeySeg::StringSeg(key), DbKeySeg::AddressSeg(owner)]
            if key == BALANCE_STORAGE_KEY =>
        {
            Some(owner)
        }
        _ => None,
    }
}

/// A simple bilateral token transfer
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Hash,
    Eq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct Transfer {
    /// Source address will spend the tokens
    pub source: Address,
    /// Target address will receive the tokens
    pub target: Address,
    /// Token's address
    pub token: Address,
    /// The amount of tokens
    pub amount: Amount,
}

impl Transfer {
    /// Sign a transfer with a given keypair.
    pub fn sign(
        self,
        tx_code: impl AsRef<[u8]>,
        keypair: &Keypair,
    ) -> SignedTxData {
        let bytes = self
            .try_to_vec()
            .expect("Encoding unsigned transfer shouldn't fail");
        SignedTxData::new(keypair, bytes, tx_code)
    }
}
