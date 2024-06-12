//! Native validity predicates for the Namada Ethereum bridge.
//! This includes both the bridge vp and the vp for the bridge
//! pool.

mod bridge_pool_vp;
mod eth_bridge_vp;
mod nut_vp;

pub use bridge_pool_vp::BridgePool;
pub use eth_bridge_vp::EthBridge;
pub use nut_vp::NonUsableTokens;
