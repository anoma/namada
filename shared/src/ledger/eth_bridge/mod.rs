//! Validity predicate and storage keys for the Ethereum bridge account
pub mod bridge_pool_vp;
pub mod parameters;
pub mod storage;
pub mod vp;

pub use namada_core::ledger::eth_bridge::{ADDRESS, INTERNAL_ADDRESS};
