//! Shared internal types between the host env and guest (wasm).

use borsh::{BorshDeserialize, BorshSerialize};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;

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
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshDeserializer)]
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

    /// Expect [`HostEnvResult::Success`].
    pub fn success_or_else<F, E>(int: i64, or_else: F) -> Result<(), E>
    where
        F: FnOnce() -> E,
    {
        if Self::is_success(int) {
            Ok(())
        } else {
            Err(or_else())
        }
    }

    /// Expect [`HostEnvResult::Success`].
    pub fn success_or<E>(int: i64, or_else: E) -> Result<(), E> {
        Self::success_or_else(int, || or_else)
    }
}

impl From<bool> for HostEnvResult {
    fn from(success: bool) -> Self {
        if success { Self::Success } else { Self::Fail }
    }
}
