//! Blockchain-level parameters for the configuration of the Ethereum bridge.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[repr(transparent)]
pub struct MinimumConfirmations(u64);

impl Default for MinimumConfirmations {
    fn default() -> Self {
        Self(100)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Config {
    /// Minimum number of confirmations needed to trust an Ethereum branch.
    /// This must be at least one.
    pub min_confirmations: MinimumConfirmations,
    /// The addresses of the Ethereum contracts that need to be directly known
    /// by validators
    pub contract_addresses: Addresses,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
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

#[derive(Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[repr(transparent)]
pub struct ContractVersion(u64);

impl Default for ContractVersion {
    fn default() -> Self {
        Self(1)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct EthereumContract {
    /// The Ethereum address of the contract e.g.
    /// 0x6B175474E89094C44Da98b954EedeAC495271d0F
    pub address: String,
    /// The version of the contract e.g. 1
    pub version: ContractVersion,
}

#[cfg(test)]
mod tests {
    use eyre::Result;

    use super::*;

    /// Ensure we can serialize and deserialize a [`Config`] struct to and from
    /// TOML. This can fail if complex fields are ordered before simple fields
    /// in any of the config structs.
    #[test]
    fn test_round_trip_toml_serde() -> Result<()> {
        let config = Config {
            min_confirmations: MinimumConfirmations::default(),
            contract_addresses: Addresses {
                native_erc20: "0x1721b337BBdd2b11f9Eef736d9192a8E9Cba5872"
                    .to_string(),
                bridge: EthereumContract {
                    address: "0x237d915037A1ba79365E84e2b8574301B6D25Ea0"
                        .to_string(),
                    version: ContractVersion::default(),
                },
                governance: EthereumContract {
                    address: "0x308728EEa73538d0edEfd95EF148Eb678F71c71D"
                        .to_string(),
                    version: ContractVersion::default(),
                },
            },
        };
        let serialized = toml::to_string(&config)?;
        let deserialized: Config = toml::from_str(&serialized)?;

        assert_eq!(config, deserialized);
        Ok(())
    }
}
