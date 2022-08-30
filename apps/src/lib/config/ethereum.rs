use serde::{Deserialize, Serialize};

/// Default [Ethereum JSON-RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/) endpoint used by the oracle
pub const DEFAULT_ORACLE_RPC_ENDPOINT: &str = "http://127.0.0.1:8545";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// The Ethereum JSON-RPC endpoint that the Ethereum event oracle will use
    /// to listen for events from the Ethereum bridge smart contracts
    pub oracle_rpc_endpoint: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            oracle_rpc_endpoint: DEFAULT_ORACLE_RPC_ENDPOINT.to_owned(),
        }
    }
}
