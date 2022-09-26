//! This module is for hashing Anoma types using the keccak
//! hash function in a way that is compatible with smart contracts
//! on Ethereum
use std::convert::TryFrom;

use borsh::{BorshDeserialize, BorshSerialize, BorshSchema};
use hex::FromHex;
use tiny_keccak::{Hasher, Keccak};

use crate::types::hash::{HASH_LENGTH, Hash, HashResult};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("TEMPORARY error: {error}")]
    Temporary { error: String },
    #[error("Failed trying to convert slice to a hash: {0}")]
    ConversionFailed(std::array::TryFromSliceError),
    #[error("Failed to convert string into a hash: {0}")]
    FromStringError(hex::FromHexError)
}

/// A Keccak hash
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct KeccakHash(pub [u8; 32]);

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
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != HASH_LENGTH {
            return Err(Error::Temporary {
                error: format!(
                    "Unexpected tx hash length {}, expected {}",
                    value.len(),
                    HASH_LENGTH
                ),
            });
        }
        let hash: [u8; 32] =
            TryFrom::try_from(value).map_err(Error::ConversionFailed)?;
        Ok(KeccakHash(hash))
    }
}

impl TryFrom<String> for KeccakHash {
    type Error = self::Error;

    fn try_from(string: String) -> HashResult<Self> {
        let bytes: Vec<u8> = Vec::from_hex(string).map_err(Error::FromStringError)?;
        Self::try_from(&bytes)
    }
}

impl TryFrom<&str> for KeccakHash {
    type Error = self::Error;

    fn try_from(string: &str) -> HashResult<Self> {
        let bytes: Vec<u8> = Vec::from_hex(string).map_err(Error::FromStringError)?;
        Self::try_from(&bytes).into()
    }
}


/// This module defines encoding methods compatible with Ethereum
/// smart contracts.
pub mod encode {
    #[doc(inline)]
    pub use ethabi::token::Token;
    use tiny_keccak::{Hasher, Keccak};

    use crate::types::ethereum_events::KeccakHash;

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
            let mut output = [0; 32];

            let mut state = Keccak::v256();
            state.update(self.encode().as_slice());
            state.finalize(&mut output);

            KeccakHash(output)
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
            return self.to_vec()
        }
    }

    // TODO: test signatures here once we merge secp keys
    #[cfg(test)]
    mod tests {
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
    }
}