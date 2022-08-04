//! This module defines encoding methods compatible with Ethereum
//! smart contracts.
// TODO: probably move this module elsewhere

// TODO: I think we are missing `uint8` types
#[doc(inline)]
pub use ethabi::token::Token;
use tiny_keccak::{Hasher, Keccak};

/// Contains a method to encode data to a format compatible with Ethereum.
pub trait Encode {
    /// The data type to be encoded to. Must deref to a hex string with
    /// a `0x` prefix.
    type EncodedData: AsRef<str>;

    /// Returns the encoded [`Token`] instances.
    fn encode(tokens: &[Token]) -> Self::EncodedData;

    /// Encodes a slice of [`Token`] instances, and returns the
    /// keccak hash of the encoded string.
    fn keccak256(tokens: &[Token]) -> [u8; 32] {
        let mut output = [0; 32];

        let mut state = Keccak::v256();
        state.update(Self::encode(tokens).as_ref().as_ref());
        state.finalize(&mut output);

        output
    }
}

/// Represents an Ethereum encoding method equivalent
/// to `abi.encode`.
pub struct AbiEncode;

impl Encode for AbiEncode {
    type EncodedData = String;

    fn encode(tokens: &[Token]) -> Self::EncodedData {
        let encoded_data = hex::encode(ethabi::encode(tokens));
        format!("0x{encoded_data}")
    }
}

/// Represents an Ethereum encoding method equivalent
/// to `abi.encodePacked`.
pub struct AbiEncodePacked;

impl Encode for AbiEncodePacked {
    type EncodedData = String;

    fn encode(_tokens: &[Token]) -> Self::EncodedData {
        todo!()
    }
}
