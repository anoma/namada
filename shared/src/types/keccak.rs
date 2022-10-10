//! This module is for hashing Namada types using the keccak256
//! hash function in a way that is compatible with smart contracts
//! on Ethereum.
use std::convert::{TryFrom, TryInto};
use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use hex::FromHex;
use thiserror::Error;
use tiny_keccak::{Hasher, Keccak};

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
    FromStringError(hex::FromHexError),
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
        let bytes: Vec<u8> =
            Vec::from_hex(string).map_err(TryFromError::FromStringError)?;
        Self::try_from(bytes.as_slice())
    }
}

/// Hash bytes using Keccak
pub fn keccak_hash(bytes: &[u8]) -> KeccakHash {
    let mut output = [0; 32];

    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);

    KeccakHash(output)
}

/// This module defines encoding methods compatible with Ethereum
/// smart contracts.
pub mod encode {
    #[doc(inline)]
    pub use ethabi::token::Token;
    use tiny_keccak::{Hasher, Keccak};

    use super::*;

    /// Contains a method to encode data to a format compatible with Ethereum.
    pub trait Encode {
        /// Encodes a struct into a sequence of ABI
        /// [`Token`] instances.
        fn tokenize(&self) -> Vec<Token>;

        /// Returns the encoded [`Token`] instances.
        fn encode(&self) -> Vec<u8> {
            let tokens = self.tokenize();
            ethabi::encode(&tokens)
        }

        /// Encodes a slice of [`Token`] instances, and returns the
        /// keccak hash of the encoded string.
        fn keccak256(&self) -> KeccakHash {
            keccak_hash(self.encode().as_slice())
        }

        /// Encodes a slice of [`Token`] instances, and returns the
        /// keccak hash of the encoded string appended to an Ethereum
        /// signature header.
        fn signed_keccak256(&self) -> KeccakHash {
            let mut output = [0; 32];

            let eth_message = {
                let message = self.encode();

                let mut eth_message =
                    format!("\x19Ethereum Signed Message:\n{}", message.len())
                        .into_bytes();
                eth_message.extend_from_slice(&message);
                eth_message
            };

            let mut state = Keccak::v256();
            state.update(&eth_message);
            state.finalize(&mut output);

            KeccakHash(output)
        }
    }

    /// Represents an Ethereum encoding method equivalent
    /// to `abi.encode`.
    pub type AbiEncode<const N: usize> = [Token; N];

    impl<const N: usize> Encode for AbiEncode<N> {
        #[inline]
        fn tokenize(&self) -> Vec<Token> {
            self.to_vec()
        }
    }

    // TODO: test signatures here once we merge secp keys
    #[cfg(test)]
    mod tests {
        use std::convert::TryInto;

        use ethabi::ethereum_types::U256;

        use super::*;

        /// Checks if we get the same result as `abi.encode`, for some given
        /// input data.
        #[test]
        fn test_abi_encode() {
            let expected = "0x000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000047465737400000000000000000000000000000000000000000000000000000000";
            let expected = hex::decode(&expected[2..]).expect("Test failed");
            let got = AbiEncode::encode(&[
                Token::Uint(U256::from(42u64)),
                Token::String("test".into()),
            ]);
            assert_eq!(expected, got);
        }

        /// Sanity check our keccak hash implementation.
        #[test]
        fn test_keccak_hash_impl() {
            let expected =
                "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";
            assert_eq!(
                expected,
                &hex::encode({
                    let mut st = Keccak::v256();
                    let mut output = [0; 32];
                    st.update(b"hello");
                    st.finalize(&mut output);
                    output
                })
            );
        }

        /// Test that the methods for converting a keccak hash to/from
        /// a string type are inverses.
        #[test]
        fn test_hex_roundtrip() {
            let original = "1C8AFF950685C2ED4BC3174F3472287B56D9517B9C948127319A09A7A36DEAC8";
            let keccak_hash: KeccakHash =
                original.try_into().expect("Test failed");
            assert_eq!(keccak_hash.to_string().as_str(), original);
        }
    }
}
