//! This module is for hashing Namada types using the keccak256
//! hash function in a way that is compatible with smart contracts
//! on Ethereum.
use std::convert::{TryFrom, TryInto};
use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::HEXUPPER;
use ethabi::Token;
use thiserror::Error;
use tiny_keccak::{Hasher, Keccak};

use crate::types::eth_abi::Encode;
use crate::types::hash::{Hash, HASH_LENGTH};

/// Errors for converting / parsing Keccak hashes
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum TryFromError {
    #[error("Unexpected tx hash length {0}, expected {1}")]
    WrongLength(usize, usize),
    #[error("Failed trying to convert slice to a hash: {0}")]
    ConversionFailed(std::array::TryFromSliceError),
    #[error("Failed to convert string into a hash: {0}")]
    FromStringError(data_encoding::DecodeError),
}

/// Represents a Keccak hash.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct KeccakHash(pub [u8; 32]);

impl Display for KeccakHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}
impl From<KeccakHash> for Hash {
    fn from(hash: KeccakHash) -> Self {
        Hash(hash.0)
    }
}

impl From<Hash> for KeccakHash {
    fn from(hash: Hash) -> Self {
        KeccakHash(hash.0)
    }
}

impl TryFrom<&[u8]> for KeccakHash {
    type Error = TryFromError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != HASH_LENGTH {
            return Err(TryFromError::WrongLength(value.len(), HASH_LENGTH));
        }
        let hash: [u8; HASH_LENGTH] =
            TryFrom::try_from(value).map_err(TryFromError::ConversionFailed)?;
        Ok(KeccakHash(hash))
    }
}

impl TryFrom<String> for KeccakHash {
    type Error = TryFromError;

    fn try_from(string: String) -> Result<Self, TryFromError> {
        string.as_str().try_into()
    }
}

impl TryFrom<&str> for KeccakHash {
    type Error = TryFromError;

    fn try_from(string: &str) -> Result<Self, TryFromError> {
        let bytes: Vec<u8> = HEXUPPER
            .decode(string.as_bytes())
            .map_err(TryFromError::FromStringError)?;
        Self::try_from(bytes.as_slice())
    }
}

impl AsRef<[u8]> for KeccakHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Hash bytes using Keccak
pub fn keccak_hash<T: AsRef<[u8]>>(bytes: T) -> KeccakHash {
    let mut output = [0; 32];

    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);

    KeccakHash(output)
}

impl Encode<1> for KeccakHash {
    fn tokenize(&self) -> [Token; 1] {
        [Token::FixedBytes(self.0.to_vec())]
    }
}
