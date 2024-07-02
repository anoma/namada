//! Runtime configuration for a validator node.
#[allow(unused_imports)]
use namada_sdk::ethereum_events::EthereumEvent;
use serde::{Deserialize, Serialize};

/// Default [Ethereum JSON-RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/) endpoint used by the oracle
pub const DEFAULT_ORACLE_RPC_ENDPOINT: &str = "http://127.0.0.1:8545";

/// The default maximum number of Ethereum events the channel between
/// the oracle and the shell can hold.
pub const ORACLE_CHANNEL_BUFFER_SIZE: usize = 1000;

/// The mode in which to run the Ethereum bridge.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Mode {
    /// The oracle will listen to the Ethereum JSON-RPC endpoint as
    /// specified in the `oracle_rpc_endpoint` setting.
    RemoteEndpoint,
    /// Instead of the oracle listening for events using an Ethereum
    /// JSON-RPC endpoint, an endpoint will be exposed by the ledger
    /// itself for submission of Borsh-serialized [`EthereumEvent`]
    /// instances. Mostly useful for testing purposes.
    SelfHostedEndpoint,
    /// Do not run any components of the Ethereum bridge.
    Off,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// The mode in which to run the Ethereum node and oracle setup of this
    /// validator.
    pub mode: Mode,
    /// The Ethereum JSON-RPC endpoint that the Ethereum event oracle will use
    /// to listen for events from the Ethereum bridge smart contracts
    pub oracle_rpc_endpoint: String,
    /// The size of bounded channel between the Ethereum oracle and main
    /// ledger subprocesses. This is the number of Ethereum events that
    /// can be held in the channel. The default is 1000.
    pub channel_buffer_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::RemoteEndpoint,
            oracle_rpc_endpoint: DEFAULT_ORACLE_RPC_ENDPOINT.to_owned(),
            channel_buffer_size: ORACLE_CHANNEL_BUFFER_SIZE,
        }
    }
}
