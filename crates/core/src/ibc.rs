//! IBC-related data types

use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::{DecodePartial, HEXLOWER, HEXLOWER_PERMISSIVE};
pub use ibc::*;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

use super::address::HASH_LEN;

/// IBC token hash derived from a denomination.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[repr(transparent)]
pub struct IbcTokenHash(pub [u8; HASH_LEN]);

impl std::fmt::Display for IbcTokenHash {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0))
    }
}

impl FromStr for IbcTokenHash {
    type Err = DecodePartial;

    fn from_str(h: &str) -> Result<Self, Self::Err> {
        let mut output = [0u8; HASH_LEN];
        HEXLOWER_PERMISSIVE.decode_mut(h.as_ref(), &mut output)?;
        Ok(IbcTokenHash(output))
    }
}
