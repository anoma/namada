use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::hash::Hash;
use serde::{Deserialize, Serialize};

use crate::Tx;

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
