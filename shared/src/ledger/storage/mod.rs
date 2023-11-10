//! Ledger's state storage with key-value backed store and a merkle tree

pub use namada_core::ledger::storage::{
    mockdb, traits, write_log, PrefixIter, WlStorage, *,
};
