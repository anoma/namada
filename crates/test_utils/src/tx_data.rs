//! Types that are meant to be serialized and used as the data component of a
//! Namada transaction.

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::address::Address;
use namada_core::storage;
use namada_core::token::Amount;

/// Represents an arbitrary write to storage at the specified key. This should
/// be used alongside the test `tx_write.wasm`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct TxWriteData {
    /// The storage key to be written to.
    pub key: storage::Key,
    /// The bytes to be written.
    pub value: Vec<u8>,
}

/// Represents minting of the specified token. This should
/// be used alongside the test `tx_mint_tokens.wasm`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct TxMintData {
    /// The minter to mint the token
    pub minter: Address,
    /// The minted target
    pub target: Address,
    /// The minted token
    pub token: Address,
    /// The minted amount
    pub amount: Amount,
}
