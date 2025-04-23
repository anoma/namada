//! Fuzzy message detection MASP primitives.

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use serde::{Deserialize, Serialize};

/// FMD flag ciphertexts.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Serialize,
    Deserialize,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
)]
// TODO: remove Default derive
#[derive(Default)]
pub struct FlagCiphertext {
    inner: Vec<u8>,
}
