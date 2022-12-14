//! Types used within wasms.

use borsh::{BorshDeserialize, BorshSerialize};

use super::storage;

/// Should be passed as `tx_data` alongside `tx_write_storage_key`.
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
pub struct WriteOp {
    /// The storage key to be written to.
    pub key: storage::Key,
    /// The bytes to be written.
    pub value: Vec<u8>,
}
