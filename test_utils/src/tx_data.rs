//! Types that are meant to be serialized and used as the data component of a
//! Namada transaction.

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::types::storage;

/// Represents an arbitrary write to storage at the specified key. This should
/// be used alongside the test `tx_write.wasm`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct TxWriteData {
    /// The storage key to be written to.
    pub key: storage::Key,
    /// The bytes to be written.
    pub value: Vec<u8>,
}
