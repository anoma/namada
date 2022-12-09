//! Ledger's state storage with key-value backed store and a merkle tree

pub mod write_log;

#[cfg(any(test, feature = "testing"))]
pub use namada_core::ledger::storage::mockdb;
pub use namada_core::ledger::storage::{traits, *};
