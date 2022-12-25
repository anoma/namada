//! Ledger's state storage with key-value backed store and a merkle tree

#[cfg(any(test, feature = "testing"))]
pub use namada_core::ledger::storage::mockdb;
pub use namada_core::ledger::storage::{traits, wl_storage, write_log, *};
pub use wl_storage::{PrefixIter, RoWlStorage, RwWlStorage, WlStorage};
