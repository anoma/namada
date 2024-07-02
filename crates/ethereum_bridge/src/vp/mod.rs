//! Native validity predicates for the Namada Ethereum bridge.
//! This includes both the bridge vp and the vp for the bridge
//! pool.

mod bridge_pool_vp;
mod eth_bridge_vp;
mod nut_vp;

pub use bridge_pool_vp::{BridgePool, Error as BridgePoolError};
pub use eth_bridge_vp::{Error as EthBridgeError, EthBridge};
pub use nut_vp::{Error as NutError, NonUsableTokens};
