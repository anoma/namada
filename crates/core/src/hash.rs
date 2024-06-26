//! Types for working with 32 bytes hashes.

use std::fmt::{self, Display};
use std::str::FromStr;

use arse_merkle_tree::traits::Hasher;
use arse_merkle_tree::H256;
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::HEXUPPER;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
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

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialOrd,
    Ord,
    Hash,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
)]
/// A hash, typically a sha-2 hash of a tx
pub struct Hash(pub [u8; HASH_LENGTH]);

impl arse_merkle_tree::traits::Value for Hash {
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn zero() -> Self {
        Hash([0u8; 32])
    }
}

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

#[allow(clippy::len_without_is_empty)]
impl Hash {
    /// Compute sha256 of some bytes
    pub fn sha256(data: impl AsRef<[u8]>) -> Self {
        let digest = Sha256::digest(data.as_ref());
        Self(*digest.as_ref())
    }

    /// Return zeros
    pub fn zero() -> Self {
        Self([0u8; HASH_LENGTH])
    }

    /// Check if the hash is all zeros
    pub fn is_zero(&self) -> bool {
        self == &Self::zero()
    }

    /// Return the length of the hash.
    pub const fn len(&self) -> usize {
        HASH_LENGTH
    }

    /// Convert this [`struct@Hash`] to a [`Vec`].
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Return the inner pointer to the hash data.
    pub const fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    /// Given hashes A and B, compute Sha256(A||B),
    /// but if one value is the zero hash, the other
    /// value is returned.
    pub fn concat(self, rhs: &Hash) -> Self {
        if self.is_zero() {
            *rhs
        } else if rhs.is_zero() {
            self
        } else {
            let mut hasher = Sha256::default();
            hasher.update(self.as_ref());
            hasher.update(rhs.as_ref());
            Self(hasher.finalize().into())
        }
    }
}

impl From<Hash> for crate::tendermint::Hash {
    fn from(hash: Hash) -> Self {
        Self::Sha256(hash.0)
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

/// The storage hasher used for the merkle tree.
pub trait StorageHasher: Hasher + fmt::Debug + Default {
    /// Hash the value to store
    fn hash(value: impl AsRef<[u8]>) -> H256;
}

/// The storage hasher used for the merkle tree.
#[derive(Default)]
pub struct Sha256Hasher(Sha256);

impl Hasher for Sha256Hasher {
    fn write_bytes(&mut self, h: &[u8]) {
        self.0.update(h)
    }

    fn finish(self) -> H256 {
        let hash = self.0.finalize();
        let bytes: [u8; 32] = hash
            .as_slice()
            .try_into()
            .expect("Sha256 output conversion to fixed array shouldn't fail");
        bytes.into()
    }

    fn hash_op() -> ics23::HashOp {
        ics23::HashOp::Sha256
    }
}

impl StorageHasher for Sha256Hasher {
    fn hash(value: impl AsRef<[u8]>) -> H256 {
        let mut hasher = Sha256::new();
        hasher.update(value.as_ref());
        let hash = hasher.finalize();
        let bytes: [u8; 32] = hash
            .as_slice()
            .try_into()
            .expect("Sha256 output conversion to fixed array shouldn't fail");
        bytes.into()
    }
}

impl fmt::Debug for Sha256Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Hasher")
    }
}

/// A Keccak hasher algorithm.
pub struct KeccakHasher(tiny_keccak::Keccak);

impl fmt::Debug for KeccakHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeccakHasher")
    }
}

impl Default for KeccakHasher {
    fn default() -> Self {
        Self(tiny_keccak::Keccak::v256())
    }
}

impl StorageHasher for KeccakHasher {
    fn hash(value: impl AsRef<[u8]>) -> H256 {
        use tiny_keccak::{Hasher, Keccak};

        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(value.as_ref());
        hasher.finalize(&mut output);
        output.into()
    }
}

impl Hasher for KeccakHasher {
    fn write_bytes(&mut self, h: &[u8]) {
        use tiny_keccak::Hasher;

        self.0.update(h);
    }

    fn finish(self) -> H256 {
        use tiny_keccak::Hasher;
        let mut output = [0; 32];

        self.0.finalize(&mut output);
        output.into()
    }
}

/// A [`StorageHasher`] which can never be called.
#[derive(Debug)]
pub enum DummyHasher {}

const DUMMY_HASHER_PANIC_MSG: &str = "A storage hasher was called, which \
                                      should never have been reachable from \
                                      any code path";

impl Default for DummyHasher {
    fn default() -> Self {
        unreachable!("{DUMMY_HASHER_PANIC_MSG}")
    }
}

impl StorageHasher for DummyHasher {
    fn hash(_: impl AsRef<[u8]>) -> H256 {
        unreachable!("{DUMMY_HASHER_PANIC_MSG}")
    }
}

impl Hasher for DummyHasher {
    fn write_bytes(&mut self, _: &[u8]) {
        unreachable!("{DUMMY_HASHER_PANIC_MSG}")
    }

    fn finish(self) -> H256 {
        unreachable!("{DUMMY_HASHER_PANIC_MSG}")
    }
}

#[cfg(any(test, feature = "testing"))]
/// Tests and strategies for hashes
pub mod testing {
    use proptest::prop_compose;

    use super::*;

    prop_compose! {
        /// Generate an arbitrary hash
        pub fn arb_hash()(bytes: [u8; 32]) -> Hash {
            Hash(bytes)
        }
    }
}

#[cfg(test)]
/// Tests and strategies for hashes
pub mod tests {
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
