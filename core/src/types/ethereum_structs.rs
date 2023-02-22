//! Ethereum bridge struct re-exports and types to do with ethereum.
use std::fmt;
use std::num::NonZeroU64;
use std::ops::{Add, AddAssign, Deref};

use borsh::{BorshDeserialize, BorshSerialize};
pub use ethbridge_structs::*;
use num256::Uint256;

/// This type must be able to represent any valid Ethereum block height. It must
/// also be Borsh serializeable, so that it can be stored in blockchain storage.
///
/// In Ethereum, the type for block height is an arbitrary precision integer - see <https://github.com/ethereum/go-ethereum/blob/v1.10.26/core/types/block.go#L79>.
#[derive(Default, Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BlockHeight {
    inner: Uint256,
}

impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl From<u64> for BlockHeight {
    fn from(value: u64) -> Self {
        Self {
            inner: Uint256::from(value),
        }
    }
}

impl From<NonZeroU64> for BlockHeight {
    fn from(value: NonZeroU64) -> Self {
        Self {
            inner: Uint256::from(value.get()),
        }
    }
}

impl From<Uint256> for BlockHeight {
    fn from(value: Uint256) -> Self {
        Self { inner: value }
    }
}

impl From<BlockHeight> for Uint256 {
    fn from(value: BlockHeight) -> Self {
        value.inner
    }
}

impl<'a> From<&'a BlockHeight> for &'a Uint256 {
    fn from(height: &'a BlockHeight) -> Self {
        &height.inner
    }
}

impl Add for BlockHeight {
    type Output = BlockHeight;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner + rhs.inner,
        }
    }
}

impl AddAssign for BlockHeight {
    fn add_assign(&mut self, rhs: Self) {
        self.inner += rhs.inner;
    }
}

impl Deref for BlockHeight {
    type Target = Uint256;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl BorshSerialize for BlockHeight {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let be = self.inner.to_bytes_be();
        BorshSerialize::serialize(&be, writer)
    }
}

impl BorshDeserialize for BlockHeight {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let be: Vec<u8> = BorshDeserialize::deserialize(buf)?;
        Ok(Self {
            inner: Uint256::from_bytes_be(&be),
        })
    }
}
