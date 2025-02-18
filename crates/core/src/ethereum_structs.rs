//! Ethereum bridge struct re-exports and types to do with ethereum.

use std::fmt;
use std::io::Read;
use std::num::NonZeroU64;
use std::ops::Deref;

use borsh::{BorshDeserialize, BorshSerialize};
pub use ethbridge_structs::*;
use num256::Uint256;
use serde::{Deserialize, Serialize};

/// This type must be able to represent any valid Ethereum block height. It must
/// also be Borsh serializeable, so that it can be stored in blockchain storage.
///
/// In Ethereum, the type for block height is an arbitrary precision integer - see <https://github.com/ethereum/go-ethereum/blob/v1.10.26/core/types/block.go#L79>.
#[derive(
    Default,
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
)]
#[repr(transparent)]
pub struct BlockHeight(Uint256);

impl BlockHeight {
    /// Get the next block height.
    ///
    /// # Panic
    ///
    /// Panics on overflow.
    pub fn next(&self) -> Self {
        self.unchecked_add(1_u64)
    }

    /// Unchecked epoch addition.
    ///
    /// # Panic
    ///
    /// Panics on overflow. Care must be taken to only use this with trusted
    /// values that are known to be in a limited range (e.g. system parameters
    /// but not e.g. transaction variables).
    pub fn unchecked_add(&self, rhs: impl Into<BlockHeight>) -> Self {
        use num_traits::CheckedAdd;
        Self(
            self.0
                .checked_add(&rhs.into())
                .expect("Block height addition shouldn't overflow"),
        )
    }
}

impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for BlockHeight {
    fn from(value: u64) -> Self {
        Self(Uint256::from(value))
    }
}

impl From<NonZeroU64> for BlockHeight {
    fn from(value: NonZeroU64) -> Self {
        Self(Uint256::from(value.get()))
    }
}

impl From<Uint256> for BlockHeight {
    fn from(value: Uint256) -> Self {
        Self(value)
    }
}

impl From<BlockHeight> for Uint256 {
    fn from(BlockHeight(value): BlockHeight) -> Self {
        value
    }
}

impl<'a> From<&'a BlockHeight> for &'a Uint256 {
    fn from(BlockHeight(height): &'a BlockHeight) -> Self {
        height
    }
}

impl Deref for BlockHeight {
    type Target = Uint256;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl BorshSerialize for BlockHeight {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let be = self.0.to_be_bytes();
        BorshSerialize::serialize(&be, writer)
    }
}

impl BorshDeserialize for BlockHeight {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let be: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        Ok(Self(Uint256::from_be_bytes(&be)))
    }
}
