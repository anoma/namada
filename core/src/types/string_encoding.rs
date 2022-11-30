//! Namada's standard string encoding for public types.
//!
//! We're using [bech32m](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki),
//! a format with a human-readable, followed by base32 encoding with a limited
//! character set with checksum check.
//!
//! To use this encoding for a new type, add a HRP (human-readable part) const
//! below and use it to `impl string_encoding::Format for YourType`.

use bech32::{self, FromBase32, ToBase32, Variant};
use thiserror::Error;

/// We're using "Bech32m" variant
pub const BECH32M_VARIANT: bech32::Variant = Variant::Bech32m;

// Human-readable parts of Bech32m encoding
//
// Invariant: HRPs must be unique !!!
//
// TODO: remove "test" suffix for live network
/// `Address` human-readable part
pub const ADDRESS_HRP: &str = "atest";
/// MASP extended viewing key human-readable part
pub const MASP_EXT_FULL_VIEWING_KEY_HRP: &str = "xfvktest";
/// MASP payment address (not pinned) human-readable part
pub const MASP_PAYMENT_ADDRESS_HRP: &str = "patest";
/// MASP pinned payment address human-readable part
pub const MASP_PINNED_PAYMENT_ADDRESS_HRP: &str = "ppatest";
/// MASP extended spending key human-readable part
pub const MASP_EXT_SPENDING_KEY_HRP: &str = "xsktest";
/// `common::PublicKey` human-readable part
pub const COMMON_PK_HRP: &str = "pktest";
/// `DkgPublicKey` human-readable part
pub const DKG_PK_HRP: &str = "dpktest";

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("Error decoding from Bech32m: {0}")]
    DecodeBech32(bech32::Error),
    #[error("Error decoding from base32: {0}")]
    DecodeBase32(bech32::Error),
    #[error("Unexpected Bech32m human-readable part {0}, expected {1}")]
    UnexpectedBech32Hrp(String, String),
    #[error("Unexpected Bech32m variant {0:?}, expected {BECH32M_VARIANT:?}")]
    UnexpectedBech32Variant(bech32::Variant),
    #[error("Invalid bytes: {0}")]
    InvalidBytes(std::io::Error),
}

/// Format to string with bech32m
pub trait Format: Sized {
    /// Human-readable part
    const HRP: &'static str;

    /// Encode `Self` to a string
    fn encode(&self) -> String {
        let base32 = self.to_bytes().to_base32();
        bech32::encode(Self::HRP, base32, BECH32M_VARIANT).unwrap_or_else(
            |_| {
                panic!(
                    "The human-readable part {} should never cause a failure",
                    Self::HRP
                )
            },
        )
    }

    /// Try to decode `Self` from a string
    fn decode(string: impl AsRef<str>) -> Result<Self, DecodeError> {
        let (hrp, hash_base32, variant) = bech32::decode(string.as_ref())
            .map_err(DecodeError::DecodeBech32)?;
        if hrp != Self::HRP {
            return Err(DecodeError::UnexpectedBech32Hrp(
                hrp,
                Self::HRP.into(),
            ));
        }
        match variant {
            BECH32M_VARIANT => {}
            _ => return Err(DecodeError::UnexpectedBech32Variant(variant)),
        }
        let bytes: Vec<u8> = FromBase32::from_base32(&hash_base32)
            .map_err(DecodeError::DecodeBase32)?;

        Self::decode_bytes(&bytes).map_err(DecodeError::InvalidBytes)
    }

    /// Encode `Self` to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Try to decode `Self` from bytes
    fn decode_bytes(bytes: &[u8]) -> Result<Self, std::io::Error>;
}

/// Implement [`std::fmt::Display`] and [`std::str::FromStr`] via
/// [`Format`].
#[macro_export]
macro_rules! impl_display_and_from_str_via_format {
    ($t:path) => {
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{}",
                    $crate::types::string_encoding::Format::encode(self)
                )
            }
        }

        impl std::str::FromStr for $t {
            type Err = $crate::types::string_encoding::DecodeError;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                $crate::types::string_encoding::Format::decode(s)
            }
        }
    };
}

/// Get the length of the human-readable part
// Not in the `Format` trait, cause functions in traits cannot be const
pub const fn hrp_len<T: Format>() -> usize {
    T::HRP.len()
}
