//! Blockchain-level parameters for the configuration of the Ethereum bridge.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[repr(transparent)]
pub struct MinimumConfirmations(u64);

impl Default for MinimumConfirmations {
    fn default() -> Self {
        Self(1)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    /// Minimum number of confirmations needed to trust an Ethereum branch.
    /// This must be at least one.
    pub min_confirmations: MinimumConfirmations,
    /// The addresses of the Ethereum contracts that need to be directly known
    /// by validators
    pub contract_addresses: Addresses,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Addresses {
    /// The Ethereum address of the ERC20 contract that represents this chain's
    /// native token e.g. 0x6B175474E89094C44Da98b954EedeAC495271d0F
    pub native_erc20: String,
    /// The Ethereum address of the bridge contract e.g.
    /// 0x6B175474E89094C44Da98b954EedeAC495271d0F
    pub bridge: EthereumContract,
    /// The Ethereum address of the governance contract e.g.
    /// 0x6B175474E89094C44Da98b954EedeAC495271d0F
    pub governance: EthereumContract,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[repr(transparent)]
pub struct ContractVersion(u64);

impl Default for ContractVersion {
    fn default() -> Self {
        Self(1)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EthereumContract {
    /// The Ethereum address of the contract e.g.
    /// 0x6B175474E89094C44Da98b954EedeAC495271d0F
    pub address: String,
    /// The version of the contract e.g. 1
    pub version: ContractVersion,
}
