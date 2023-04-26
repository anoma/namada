//! Types that are used in validity predicates.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::proto::Tx;
use crate::types::hash::Hash;

/// A validity predicate with an input that is intended to be invoked via `eval`
/// host function.
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct EvalVp {
    /// The VP code hash to `eval`
    pub vp_code_hash: Hash,
    /// The input for the `eval`ed VP
    pub input: Tx,
}
