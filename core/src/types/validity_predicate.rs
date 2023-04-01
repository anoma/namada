//! Types that are used in validity predicates.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use crate::proto::{Tx, SignedTxData};

/// A validity predicate with an input that is intended to be invoked via `eval`
/// host function.
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct EvalVp {
    /// The VP code to `eval`
    pub vp_code: Vec<u8>,
    /// The input for the `eval`ed VP
    pub input: Tx,
}
