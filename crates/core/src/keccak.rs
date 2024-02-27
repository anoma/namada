//! This module is for hashing Namada types using the keccak256
//! hash function in a way that is compatible with smart contracts
//! on Ethereum.
use std::fmt;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::HEXUPPER;
use ethabi::Token;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
pub use tiny_keccak::{Hasher, Keccak};

use crate::eth_abi::Encode;
use crate::hash::{Hash, HASH_LENGTH};

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

impl KeccakHash {
    /// Check if this [`KeccakHash`] is comprised solely of bytes with
    /// a value of zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }
}

impl fmt::Display for KeccakHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl Serialize for KeccakHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for KeccakHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KeccakVisitor;

        impl<'de> de::Visitor<'de> for KeccakVisitor {
            type Value = KeccakHash;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a string containing a keccak hash")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                KeccakHash::try_from(s).map_err(|_| {
                    de::Error::invalid_value(de::Unexpected::Str(s), &self)
                })
            }
        }

        deserializer.deserialize_str(KeccakVisitor)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak_serde_roundtrip() {
        let mut hash = KeccakHash([0; 32]);

        for i in 0..32 {
            hash.0[i] = i as u8;
        }

        let serialized = serde_json::to_string(&hash).unwrap();
        let deserialized: KeccakHash =
            serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized, hash);
    }
}
