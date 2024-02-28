//! Ethereum bridge struct re-exports and types to do with ethereum.
use std::fmt;
use std::io::Read;
use std::num::NonZeroU64;
use std::ops::{Add, AddAssign, Deref};

use borsh::{BorshDeserialize, BorshSerialize};
pub use ethbridge_structs::*;
use num256::Uint256;
use serde::{Deserialize, Serialize};

use crate::keccak::KeccakHash;

/// Status of some Bridge pool transfer.
#[derive(
    Hash,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub enum BpTransferStatus {
    /// The transfer has been relayed.
    Relayed,
    /// The transfer has expired.
    Expired,
}

/// Ethereum bridge events on Namada's event log.
#[derive(
    Hash,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub enum EthBridgeEvent {
    /// Bridge pool transfer status update event.
    BridgePool {
        /// Hash of the Bridge pool transfer.
        tx_hash: KeccakHash,
        /// Status of the Bridge pool transfer.
        status: BpTransferStatus,
    },
}

impl EthBridgeEvent {
    /// Return a new Bridge pool expired transfer event.
    pub const fn new_bridge_pool_expired(tx_hash: KeccakHash) -> Self {
        Self::BridgePool {
            tx_hash,
            status: BpTransferStatus::Expired,
        }
    }

    /// Return a new Bridge pool relayed transfer event.
    pub const fn new_bridge_pool_relayed(tx_hash: KeccakHash) -> Self {
        Self::BridgePool {
            tx_hash,
            status: BpTransferStatus::Relayed,
        }
    }
}

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

impl Add for BlockHeight {
    type Output = BlockHeight;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for BlockHeight {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
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
        let be = self.0.to_bytes_be();
        BorshSerialize::serialize(&be, writer)
    }
}

impl BorshDeserialize for BlockHeight {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let be: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        Ok(Self(Uint256::from_bytes_be(&be)))
    }
}
