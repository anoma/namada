//! Blockchain-level parameters for the configuration of the Ethereum bridge.
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

/// Represents a configuration value for an Ethereum address.
///
/// For instance:
/// `0x6B175474E89094C44Da98b954EedeAC495271d0F`
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[repr(transparent)]
pub struct Address(String);

/// Represents a configuration value for the minimum number of
/// confirmations an Ethereum event must reach before it can be acted on.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[repr(transparent)]
pub struct MinimumConfirmations(NonZeroU64);

impl Default for MinimumConfirmations {
    fn default() -> Self {
        Self(unsafe { NonZeroU64::new_unchecked(100) })
    }
}

/// Represents chain parameters for the Ethereum bridge.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Config {
    /// Minimum number of confirmations needed to trust an Ethereum branch.
    /// This must be at least one.
    pub min_confirmations: MinimumConfirmations,
    /// The addresses of the Ethereum contracts that need to be directly known
    /// by validators.
    pub contracts: Contracts,
}

/// Represents all the Ethereum contracts that need to be directly know about by
/// validators.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Contracts {
    /// The Ethereum address of the ERC20 contract that represents this chain's
    /// native token.
    pub native_erc20: Address,
    /// The Ethereum address of the bridge contract.
    pub bridge: UpgradeableContract,
    /// The Ethereum address of the governance contract.
    pub governance: UpgradeableContract,
}

/// Represents a configuration value for the version of a contract that can be
/// upgraded. Starts from 1.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[repr(transparent)]
pub struct ContractVersion(NonZeroU64);

impl Default for ContractVersion {
    fn default() -> Self {
        Self(unsafe { NonZeroU64::new_unchecked(1) })
    }
}

/// Represents an Ethereum contract that may be upgraded.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct UpgradeableContract {
    /// The Ethereum address of the contract.
    pub address: Address,
    /// The version of the contract. Starts from 1.
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
            contracts: Contracts {
                native_erc20: Address(
                    "0x1721b337BBdd2b11f9Eef736d9192a8E9Cba5872".to_string(),
                ),
                bridge: UpgradeableContract {
                    address: Address(
                        "0x237d915037A1ba79365E84e2b8574301B6D25Ea0"
                            .to_string(),
                    ),
                    version: ContractVersion::default(),
                },
                governance: UpgradeableContract {
                    address: Address(
                        "0x308728EEa73538d0edEfd95EF148Eb678F71c71D"
                            .to_string(),
                    ),
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
