pub mod ledger;

#[cfg(test)]
mod tests {
    use eyre::Result;
    use namada::ledger::eth_bridge::parameters::{
        ContractVersion, Contracts, EthereumBridgeConfig, MinimumConfirmations,
        UpgradeableContract,
    };
    use namada::types::ethereum_events::EthAddress;

    /// Ensure we can serialize and deserialize a [`Config`] struct to and from
    /// TOML. This can fail if complex fields are ordered before simple fields
    /// in any of the config structs.
    #[test]
    fn test_round_trip_toml_serde() -> Result<()> {
        let config = EthereumBridgeConfig {
            min_confirmations: MinimumConfirmations::default(),
            contracts: Contracts {
                native_erc20: EthAddress([42; 20]),
                bridge: UpgradeableContract {
                    address: EthAddress([23; 20]),
                    version: ContractVersion::default(),
                },
                governance: UpgradeableContract {
                    address: EthAddress([18; 20]),
                    version: ContractVersion::default(),
                },
            },
        };
        let serialized = toml::to_string(&config)?;
        let deserialized: EthereumBridgeConfig = toml::from_str(&serialized)?;

        assert_eq!(config, deserialized);
        Ok(())
    }
}
