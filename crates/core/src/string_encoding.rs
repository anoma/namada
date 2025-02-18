//! Namada's standard string encoding for public types.
//!
//! We're using [bech32m](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki),
//! a format with a human-readable, followed by base32 encoding with a limited
//! character set with checksum check.
//!
//! To use this encoding for a new type, add a HRP (human-readable part) const
//! below and use it to `impl string_encoding::Format for YourType`.

use std::fmt::Display;
use std::ops::Deref;
use std::str::FromStr;

use bech32::Bech32m;
pub use bech32::Hrp;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Human-readable parts of Bech32m encoding
//
// Invariant: HRPs must be unique !!!
//
/// `Address` human-readable part
pub const ADDRESS_HRP: &str = "tnam";
/// MASP extended viewing key human-readable part
pub const MASP_EXT_FULL_VIEWING_KEY_HRP: &str = "zvknam";
/// MASP payment address human-readable part
pub const MASP_PAYMENT_ADDRESS_HRP: &str = "znam";
/// MASP extended spending key human-readable part
pub const MASP_EXT_SPENDING_KEY_HRP: &str = "zsknam";
/// `common::PublicKey` human-readable part
pub const COMMON_PK_HRP: &str = "tpknam";
/// `common::Signature` human-readable part
pub const COMMON_SIG_HRP: &str = "signam";

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("Error decoding from Bech32m: {0}")]
    DecodeBech32(bech32::DecodeError),
    #[error("Unexpected Bech32m human-readable part {0}, expected {1}")]
    UnexpectedBech32Hrp(String, String),
    #[error("Invalid address encoding: {0}")]
    InvalidInnerEncoding(String),
    #[error("Invalid bytes: {0}")]
    InvalidBytes(std::io::Error),
    #[error("Unexpected discriminant byte: {0}")]
    UnexpectedDiscriminant(u8),
}

/// Format to string with bech32m
pub trait Format: Sized {
    /// Human-readable part
    const HRP: Hrp;

    /// Encoded bytes representation of `Self`.
    type EncodedBytes<'a>: AsRef<[u8]>
    where
        Self: 'a;

    /// Encode `Self` to a string
    fn encode(&self) -> String {
        bech32::encode::<Bech32m>(Self::HRP, self.to_bytes().as_ref())
            .unwrap_or_else(|_| {
                panic!(
                    "The human-readable part {} should never cause a failure",
                    Self::HRP
                )
            })
    }

    /// Try to decode `Self` from a string
    fn decode(string: impl AsRef<str>) -> Result<Self, DecodeError> {
        let (hrp, bytes) = bech32::decode(string.as_ref())
            .map_err(DecodeError::DecodeBech32)?;
        if hrp != Self::HRP {
            return Err(DecodeError::UnexpectedBech32Hrp(
                hrp.to_string(),
                Self::HRP.to_string(),
            ));
        }
        Self::decode_bytes(&bytes)
    }

    /// Encode `Self` to bytes
    fn to_bytes(&self) -> Self::EncodedBytes<'_>;

    /// Try to decode `Self` from bytes
    fn decode_bytes(bytes: &[u8]) -> Result<Self, DecodeError>;
}

/// Implement [`std::fmt::Display`] and [`std::str::FromStr`] via
/// [`Format`].
#[macro_export]
macro_rules! impl_display_and_from_str_via_format {
    ($t:path) => {
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", $crate::string_encoding::Format::encode(self))
            }
        }

        impl std::str::FromStr for $t {
            type Err = $crate::string_encoding::DecodeError;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                $crate::string_encoding::Format::decode(s)
            }
        }
    };
}

// Not const in bench32 0.10. Requires <https://github.com/rust-bitcoin/rust-bech32/pull/212>
// /// Get the length of the human-readable part
// // Not in the `Format` trait, cause functions in traits cannot be const
// pub const fn hrp_len<T: Format>() -> usize {
//     T::HRP.len()
// }

/// Wrapper for `T` to serde encode via `Display` and decode via `FromStr`
#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
#[serde(transparent)]
pub struct StringEncoded<T>
where
    T: FromStr + Display,
    <T as FromStr>::Err: Display,
{
    /// Raw value
    #[serde(
        serialize_with = "encode_via_display",
        deserialize_with = "decode_via_from_str"
    )]
    pub raw: T,
}

impl<T> StringEncoded<T>
where
    T: FromStr + Display,
    <T as FromStr>::Err: Display,
{
    /// Wrap to make `T` string encoded
    pub fn new(raw: T) -> Self {
        Self { raw }
    }
}

impl<T> Deref for StringEncoded<T>
where
    T: FromStr + Display,
    <T as FromStr>::Err: Display,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl<T> Display for StringEncoded<T>
where
    T: FromStr + Display,
    <T as FromStr>::Err: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.raw.fmt(f)
    }
}

impl<T> FromStr for StringEncoded<T>
where
    T: FromStr + Display,
    <T as FromStr>::Err: Display,
{
    type Err = <T as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = T::from_str(s)?;
        Ok(Self { raw })
    }
}

fn encode_via_display<S, T>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: Display,
{
    let val_str = val.to_string();
    serde::Serialize::serialize(&val_str, serializer)
}

fn decode_via_from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromStr,
    <T as FromStr>::Err: Display,
{
    let val_str: String = serde::Deserialize::deserialize(deserializer)?;
    FromStr::from_str(&val_str).map_err(serde::de::Error::custom)
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn test_hrps() {
        // Make sure that all HRPs are valid
        assert!(Hrp::parse(ADDRESS_HRP).is_ok());
        assert!(Hrp::parse(MASP_EXT_FULL_VIEWING_KEY_HRP).is_ok());
        assert!(Hrp::parse(MASP_PAYMENT_ADDRESS_HRP).is_ok());
        assert!(Hrp::parse(MASP_EXT_SPENDING_KEY_HRP).is_ok());
        assert!(Hrp::parse(COMMON_PK_HRP).is_ok());
        assert!(Hrp::parse(COMMON_SIG_HRP).is_ok());
    }
}

/// Testing helpers
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use core::fmt::Debug;

    use super::Format;

    /// String encoding roundtrip test
    pub fn test_string_formatting<T: Format + Eq + Debug>(val: &T) {
        let str = Format::encode(val);
        let decoded: T = Format::decode(str).unwrap();
        assert_eq!(val, &decoded)
    }
}
