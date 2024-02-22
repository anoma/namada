//! This module contains functionality for handling protocol transactions.
//!
//! When a protocol transaction is included in a block, we may expect all nodes
//! to update their blockchain state in a deterministic way. This can be done
//! natively rather than via the wasm environment as happens with regular
//! transactions.
pub mod bridge_pool_roots;
pub mod ethereum_events;
mod read;
mod update;
mod utils;
pub mod validator_set_update;
pub mod votes;

use std::collections::BTreeSet;

use namada_core::storage;

/// The keys changed while applying a protocol transaction.
pub type ChangedKeys = BTreeSet<storage::Key>;
