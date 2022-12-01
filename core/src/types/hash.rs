//! Types for working with 32 bytes hashes.

use std::fmt::{self, Display};
use std::ops::Deref;
use std::str::FromStr;

use arse_merkle_tree::traits::Value;
use arse_merkle_tree::H256;
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::HEXUPPER;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The length of the transaction hash string
pub const HASH_LENGTH: usize = 32;

/// The length of the hex encoded transaction hash.
pub const HEX_HASH_LENGTH: usize = HASH_LENGTH * 2;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("TEMPORARY error: {error}")]
    Temporary { error: String },
    #[error("Failed trying to convert slice to a hash: {0}")]
    ConversionFailed(std::array::TryFromSliceError),
    #[error("Failed to convert string into a hash: {0}")]
    FromStringError(data_encoding::DecodeError),
}

/// Result for functions that may fail
pub type HashResult<T> = std::result::Result<T, Error>;

#[derive(
    Clone,
    Debug,
    Default,
    Hash,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
/// A hash, typically a sha-2 hash of a tx
pub struct Hash(pub [u8; HASH_LENGTH]);

impl Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", HEXUPPER.encode(&self.0))
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Hash {
    type Target = [u8; HASH_LENGTH];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for Hash {
    type Error = self::Error;

    fn try_from(value: &[u8]) -> HashResult<Self> {
        if value.len() != HASH_LENGTH {
            return Err(Error::Temporary {
                error: format!(
                    "Unexpected tx hash length {}, expected {}",
                    value.len(),
                    HASH_LENGTH
                ),
            });
        }
        let hash: [u8; HASH_LENGTH] =
            TryFrom::try_from(value).map_err(Error::ConversionFailed)?;
        Ok(Hash(hash))
    }
}

impl TryFrom<String> for Hash {
    type Error = self::Error;

    fn try_from(string: String) -> HashResult<Self> {
        string.as_str().try_into()
    }
}

impl TryFrom<&str> for Hash {
    type Error = self::Error;

    fn try_from(string: &str) -> HashResult<Self> {
        let vec = HEXUPPER
            .decode(string.to_uppercase().as_ref())
            .map_err(Error::FromStringError)?;
        Self::try_from(&vec[..])
    }
}

impl FromStr for Hash {
    type Err = self::Error;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        Self::try_from(str)
    }
}

impl Hash {
    /// Compute sha256 of some bytes
    pub fn sha256(data: impl AsRef<[u8]>) -> Self {
        let digest = Sha256::digest(data.as_ref());
        Self(*digest.as_ref())
    }

    fn zero() -> Self {
        Self([0u8; HASH_LENGTH])
    }

    /// Check if the hash is all zeros
    pub fn is_zero(&self) -> bool {
        self == &Self::zero()
    }
}

#[cfg(any(feature = "tendermint", feature = "tendermint-abcipp"))]
impl From<Hash> for crate::tendermint::abci::transaction::Hash {
    fn from(hash: Hash) -> Self {
        Self::new(hash.0)
    }
}

#[cfg(any(feature = "tendermint", feature = "tendermint-abcipp"))]
impl From<Hash> for crate::tendermint::Hash {
    fn from(hash: Hash) -> Self {
        Self::Sha256(hash.0)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest::string::{string_regex, RegexGeneratorStrategy};

    use super::*;

    /// Returns a proptest strategy that yields hex encoded hashes.
    fn hex_encoded_hash_strat() -> RegexGeneratorStrategy<String> {
        string_regex(r"[a-fA-F0-9]{64}").unwrap()
    }

    proptest! {
        #[test]
        fn test_hash_string(hex_hash in hex_encoded_hash_strat()) {
            let _: Hash = hex_hash.try_into().unwrap();
        }
    }
}

impl Value for Hash {
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn zero() -> Self {
        Hash([0u8; HASH_LENGTH])
    }
}

impl From<Hash> for H256 {
    fn from(hash: Hash) -> Self {
        hash.0.into()
    }
}

impl From<H256> for Hash {
    fn from(hash: H256) -> Self {
        Self(hash.into())
    }
}

impl From<&H256> for Hash {
    fn from(hash: &H256) -> Self {
        let hash = hash.to_owned();
        Self(hash.into())
    }
}
