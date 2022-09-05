//! Configuration settings to do with the Ethereum bridge.
#[allow(unused_imports)]
use namada::types::ethereum_events::EthereumEvent;
use serde::{Deserialize, Serialize};

/// Default [Ethereum JSON-RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/) endpoint used by the oracle
pub const DEFAULT_ORACLE_RPC_ENDPOINT: &str = "http://127.0.0.1:8545";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// The Ethereum JSON-RPC endpoint that the Ethereum event oracle will use
    /// to listen for events from the Ethereum bridge smart contracts
    pub oracle_rpc_endpoint: String,
    /// If this is set to `true`, then instead of the oracle listening for
    /// events at a Ethereum JSON-RPC endpoint, an endpoint will be exposed by
    /// the ledger for submission of Borsh-serialized
    /// [`EthereumEvent`]s
    #[cfg(not(feature = "eth-fullnode"))]
    pub oracle_event_endpoint: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            oracle_rpc_endpoint: DEFAULT_ORACLE_RPC_ENDPOINT.to_owned(),
            #[cfg(not(feature = "eth-fullnode"))]
            oracle_event_endpoint: false,
        }
    }
}
