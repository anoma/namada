//! Blockchain-level parameters for the configuration of the Ethereum bridge.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    /// Minimum number of confirmations needed to trust an Ethereum branch.
    /// This must be at least one.
    pub min_confirmations: u64,
    /// The addresses of the Ethereum contracts that need to be directly known
    /// by validators
    pub contract_addresses: Addresses,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Addresses {
    /// The Ethereum address of the proxy contract e.g.
    /// 0x6B175474E89094C44Da98b954EedeAC495271d0F
    pub proxy: String,
    /// The Ethereum address of the ERC20 contract that represents this chain's
    /// native token e.g. 0x6B175474E89094C44Da98b954EedeAC495271d0F
    pub native_erc20: String,
}
