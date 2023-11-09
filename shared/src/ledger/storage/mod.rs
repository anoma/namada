//! Ledger's state storage with key-value backed store and a merkle tree

pub use namada_core::ledger::storage::mockdb;
pub use namada_core::ledger::storage::{
    traits, write_log, PrefixIter, WlStorage, *,
};
