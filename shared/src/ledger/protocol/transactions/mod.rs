//! This module contains functionality for handling protocol transactions.
//!
//! When a protocol transaction is included in a block, we may expect all nodes
//! to update their blockchain state in a deterministic way. This can be done
//! natively rather than via the wasm environment as happens with regular
//! transactions.

use std::collections::BTreeSet;

use crate::types::storage;

pub(super) mod ethereum_events;

pub(super) mod validator_set_update;

mod votes;

mod read;

mod update;

mod utils;

/// The keys changed while applying a protocol transaction.
pub type ChangedKeys = BTreeSet<storage::Key>;
