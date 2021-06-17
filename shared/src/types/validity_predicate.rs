//! Types that are used in validity predicates.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A validity predicate with an input that is intended to be invoked via `eval`
/// host function.
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct EvalVp {
    /// The VP code to `eval`
    pub vp_code: Vec<u8>,
    /// The input for the `eval`ed VP
    pub input: Vec<u8>,
}
