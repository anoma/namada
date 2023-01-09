//! Functionality for accessing the storage subspace
pub mod proof;
pub mod vote_tallies;
pub use namada_core::ledger::eth_bridge::storage::{
    bridge_pool, wrapped_erc20s, *,
};
