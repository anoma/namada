//! Shared internal types between the host env and guest (wasm).

use borsh::{BorshDeserialize, BorshSerialize};

/// A result of a wasm call to host functions that may fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostEnvResult {
    /// A success
    Success = 1,
    /// A non-fatal failure does **not** interrupt WASM execution
    Fail = -1,
}

/// Key-value pair represents data from account's subspace.
/// It is used for prefix iterator's WASM host_env functions.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct KeyVal {
    /// The storage key
    pub key: String,
    /// The value as arbitrary bytes
    pub val: Vec<u8>,
}

impl HostEnvResult {
    /// Convert result to `i64`, which can be passed to wasm
    pub fn to_i64(self) -> i64 {
        self as _
    }

    /// Check if the given result as `i64` is a success
    pub fn is_success(int: i64) -> bool {
        int == Self::Success.to_i64()
    }

    /// Check if the given result as `i64` is a non-fatal failure
    pub fn is_fail(int: i64) -> bool {
        int == Self::Fail.to_i64()
    }
}

impl From<bool> for HostEnvResult {
    fn from(success: bool) -> Self {
        if success { Self::Success } else { Self::Fail }
    }
}
