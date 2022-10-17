//! This module contains functionality for handling protocol transactions.
//!
//! When a protocol transaction is included in a block, we may expect all nodes
//! to update their blockchain state in a deterministic way. This can be done
//! natively rather than via the wasm environment as happens with regular
//! transactions.
#[cfg(not(feature = "abcipp"))]
pub(super) mod ethereum_events;
#[cfg(not(feature = "abcipp"))]
mod votes;
