//! This module defines encoding methods compatible with Ethereum
//! smart contracts.
// TODO: probably move this module elsewhere

#[doc(inline)]
pub use ethabi::token::Token;
use tiny_keccak::{Hasher, Keccak};

use crate::types::ethereum_events::KeccakHash;

/// Contains a method to encode data to a format compatible with Ethereum.
pub trait Encode {
    /// The data type to be encoded to. Must deref to a hex string with
    /// a `0x` prefix.
    type HexString: AsRef<str>;

    /// Returns the encoded [`Token`] instances.
    fn encode(tokens: &[Token]) -> Self::HexString;

    /// Encodes a slice of [`Token`] instances, and returns the
    /// keccak hash of the encoded string.
    fn keccak256(tokens: &[Token]) -> KeccakHash {
        let mut output = [0; 32];

        let mut state = Keccak::v256();
        state.update(Self::encode(tokens).as_ref().as_ref());
        state.finalize(&mut output);

        KeccakHash(output)
    }

    /// Encodes a slice of [`Token`] instances, and returns the
    /// keccak hash of the encoded string appended to an Ethereum
    /// signature header.
    fn signed_keccak256(tokens: &[Token]) -> KeccakHash {
        let mut output = [0; 32];

        let eth_message = {
            let encoded = Self::encode(tokens);
            let message: &[u8] = encoded.as_ref().as_ref();

            let mut eth_message =
                format!("\x19Ethereum Signed Message:\n{}", message.len())
                    .into_bytes();
            eth_message.extend_from_slice(message);
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
pub struct AbiEncode;

impl Encode for AbiEncode {
    type HexString = String;

    fn encode(tokens: &[Token]) -> Self::HexString {
        let encoded_data = hex::encode(ethabi::encode(tokens));
        format!("0x{encoded_data}")
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
