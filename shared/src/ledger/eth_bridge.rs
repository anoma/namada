//! Ethereum bridge utilities shared between `wasm` and the `cli`.

pub use namada_core::ledger::eth_bridge::storage::wrapped_erc20s;
pub use namada_core::ledger::eth_bridge::{ADDRESS, INTERNAL_ADDRESS};
pub use namada_ethereum_bridge::parameters::*;
pub use namada_ethereum_bridge::storage::eth_bridge_queries::*;
