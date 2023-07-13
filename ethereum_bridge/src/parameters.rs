//! Parameters for configuring the Ethereum bridge
use std::num::NonZeroU64;

use borsh::{BorshDeserialize, BorshSerialize};
use eyre::{eyre, Result};
use namada_core::ledger::eth_bridge::storage::whitelist;
use namada_core::ledger::storage;
use namada_core::ledger::storage::types::encode;
use namada_core::ledger::storage::WlStorage;
use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
use namada_core::types::ethereum_events::EthAddress;
use namada_core::types::ethereum_structs;
use namada_core::types::storage::Key;
use namada_core::types::token::DenominatedAmount;
use serde::{Deserialize, Serialize};

use crate::storage::eth_bridge_queries::{
    EthBridgeEnabled, EthBridgeQueries, EthBridgeStatus,
};
use crate::{bridge_pool_vp, storage as bridge_storage, vp};

/// An ERC20 token whitelist entry.
#[derive(
    Clone,
    Copy,
    Eq,
    PartialEq,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Erc20WhitelistEntry {
    /// The address of the whitelisted ERC20 token.
    pub token_address: EthAddress,
    /// The token cap of the whitelisted ERC20 token.
    pub token_cap: DenominatedAmount,
}

/// Represents a configuration value for the minimum number of
/// confirmations an Ethereum event must reach before it can be acted on.
#[derive(
    Clone,
    Copy,
    Eq,
    PartialEq,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[repr(transparent)]
pub struct MinimumConfirmations(NonZeroU64);

impl Default for MinimumConfirmations {
    fn default() -> Self {
        // SAFETY: The only way the API contract of `NonZeroU64` can be violated
        // is if we construct values of this type using 0 as argument.
        Self(unsafe { NonZeroU64::new_unchecked(100) })
    }
}

impl From<NonZeroU64> for MinimumConfirmations {
    fn from(value: NonZeroU64) -> Self {
        Self(value)
    }
}

impl From<MinimumConfirmations> for NonZeroU64 {
    fn from(value: MinimumConfirmations) -> Self {
        value.0
    }
}

/// Represents a configuration value for the version of a contract that can be
/// upgraded. Starts from 1.
#[derive(
    Clone,
    Copy,
    Eq,
    PartialEq,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[repr(transparent)]
pub struct ContractVersion(NonZeroU64);

impl Default for ContractVersion {
    fn default() -> Self {
        // SAFETY: The only way the API contract of `NonZeroU64` can be
        // violated is if we construct values of this type using 0 as
        // argument.
        Self(unsafe { NonZeroU64::new_unchecked(1) })
    }
}

/// Represents an Ethereum contract that may be upgraded.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct UpgradeableContract {
    /// The Ethereum address of the contract.
    pub address: EthAddress,
    /// The version of the contract. Starts from 1.
    pub version: ContractVersion,
}

/// Represents all the Ethereum contracts that need to be directly know about by
/// validators.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Contracts {
    /// The Ethereum address of the ERC20 contract that represents this chain's
    /// native token.
    pub native_erc20: EthAddress,
    /// The Ethereum address of the bridge contract.
    pub bridge: UpgradeableContract,
    /// The Ethereum address of the governance contract.
    pub governance: UpgradeableContract,
}

/// Represents chain parameters for the Ethereum bridge.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct EthereumBridgeConfig {
    /// Initial Ethereum block height when events will first be extracted from.
    pub eth_start_height: ethereum_structs::BlockHeight,
    /// Minimum number of confirmations needed to trust an Ethereum branch.
    /// This must be at least one.
    pub min_confirmations: MinimumConfirmations,
    /// List of ERC20 token types whitelisted at genesis time.
    pub erc20_whitelist: Vec<Erc20WhitelistEntry>,
    /// The addresses of the Ethereum contracts that need to be directly known
    /// by validators.
    pub contracts: Contracts,
}

impl EthereumBridgeConfig {
    /// Initialize the Ethereum bridge parameters in storage.
    ///
    /// If these parameters are initialized, the storage subspaces
    /// for the Ethereum bridge VPs are also initialized.
    pub fn init_storage<DB, H>(&self, wl_storage: &mut WlStorage<DB, H>)
    where
        DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
        H: 'static + storage::traits::StorageHasher,
    {
        let Self {
            erc20_whitelist,
            eth_start_height,
            min_confirmations,
            contracts:
                Contracts {
                    native_erc20,
                    bridge,
                    governance,
                },
        } = self;
        let active_key = bridge_storage::active_key();
        let min_confirmations_key = bridge_storage::min_confirmations_key();
        let native_erc20_key = bridge_storage::native_erc20_key();
        let bridge_contract_key = bridge_storage::bridge_contract_key();
        let governance_contract_key = bridge_storage::governance_contract_key();
        let eth_start_height_key = bridge_storage::eth_start_height_key();
        wl_storage
            .write_bytes(
                &active_key,
                encode(&EthBridgeStatus::Enabled(EthBridgeEnabled::AtGenesis)),
            )
            .unwrap();
        wl_storage
            .write_bytes(&min_confirmations_key, encode(min_confirmations))
            .unwrap();
        wl_storage
            .write_bytes(&native_erc20_key, encode(native_erc20))
            .unwrap();
        wl_storage
            .write_bytes(&bridge_contract_key, encode(bridge))
            .unwrap();
        wl_storage
            .write_bytes(&governance_contract_key, encode(governance))
            .unwrap();
        wl_storage
            .write_bytes(&eth_start_height_key, encode(eth_start_height))
            .unwrap();
        for Erc20WhitelistEntry {
            token_address: addr,
            token_cap: DenominatedAmount { amount: cap, denom },
        } in erc20_whitelist
        {
            let key = whitelist::Key {
                asset: *addr,
                suffix: whitelist::KeyType::Whitelisted,
            }
            .into();
            wl_storage.write_bytes(&key, encode(&true)).unwrap();

            let key = whitelist::Key {
                asset: *addr,
                suffix: whitelist::KeyType::Cap,
            }
            .into();
            wl_storage.write_bytes(&key, encode(cap)).unwrap();

            let key = whitelist::Key {
                asset: *addr,
                suffix: whitelist::KeyType::Denomination,
            }
            .into();
            wl_storage.write_bytes(&key, encode(denom)).unwrap();
        }
        // Initialize the storage for the Ethereum Bridge VP.
        vp::init_storage(wl_storage);
        // Initialize the storage for the Bridge Pool VP.
        bridge_pool_vp::init_storage(wl_storage);
    }
}

/// Subset of [`EthereumBridgeConfig`], containing only Ethereum
/// oracle specific parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumOracleConfig {
    /// Initial Ethereum block height when events will first be extracted from.
    pub eth_start_height: ethereum_structs::BlockHeight,
    /// Minimum number of confirmations needed to trust an Ethereum branch.
    /// This must be at least one.
    pub min_confirmations: MinimumConfirmations,
    /// The addresses of the Ethereum contracts that need to be directly known
    /// by validators.
    pub contracts: Contracts,
}

impl From<EthereumBridgeConfig> for EthereumOracleConfig {
    fn from(config: EthereumBridgeConfig) -> Self {
        let EthereumBridgeConfig {
            eth_start_height,
            min_confirmations,
            contracts,
            ..
        } = config;
        Self {
            eth_start_height,
            min_confirmations,
            contracts,
        }
    }
}

impl EthereumOracleConfig {
    /// Reads the latest [`EthereumOracleConfig`] from storage. If it is not
    /// present, `None` will be returned - this could be the case if the bridge
    /// has not been bootstrapped yet. Panics if the storage appears to be
    /// corrupt.
    pub fn read<DB, H>(wl_storage: &WlStorage<DB, H>) -> Option<Self>
    where
        DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
        H: 'static + storage::traits::StorageHasher,
    {
        // TODO(namada#1720): remove present key check; `is_bridge_active`
        // should not panic, when the active status key has not been
        // written to; simply return bridge disabled instead
        let has_active_key =
            wl_storage.has_key(&bridge_storage::active_key()).unwrap();

        if !has_active_key || !wl_storage.ethbridge_queries().is_bridge_active()
        {
            return None;
        }

        let min_confirmations_key = bridge_storage::min_confirmations_key();
        let native_erc20_key = bridge_storage::native_erc20_key();
        let bridge_contract_key = bridge_storage::bridge_contract_key();
        let governance_contract_key = bridge_storage::governance_contract_key();
        let eth_start_height_key = bridge_storage::eth_start_height_key();

        // These reads must succeed otherwise the storage is corrupt or a
        // read failed
        let min_confirmations =
            must_read_key(wl_storage, &min_confirmations_key);
        let native_erc20 = must_read_key(wl_storage, &native_erc20_key);
        let bridge_contract = must_read_key(wl_storage, &bridge_contract_key);
        let governance_contract =
            must_read_key(wl_storage, &governance_contract_key);
        let eth_start_height = must_read_key(wl_storage, &eth_start_height_key);

        Some(Self {
            eth_start_height,
            min_confirmations,
            contracts: Contracts {
                native_erc20,
                bridge: bridge_contract,
                governance: governance_contract,
            },
        })
    }
}

/// Get the Ethereum address for wNam from storage, if possible
pub fn read_native_erc20_address<S>(storage: &S) -> Result<EthAddress>
where
    S: StorageRead,
{
    let native_erc20 = bridge_storage::native_erc20_key();
    match StorageRead::read(storage, &native_erc20) {
        Ok(Some(eth_address)) => Ok(eth_address),
        Ok(None) => {
            Err(eyre!("The Ethereum bridge storage is not initialized"))
        }
        Err(e) => Err(eyre!(
            "Failed to read storage when fetching the native ERC20 address \
             with: {}",
            e.to_string()
        )),
    }
}

/// Reads the value of `key` from `storage` and deserializes it, or panics
/// otherwise.
fn must_read_key<DB, H, T: BorshDeserialize>(
    wl_storage: &WlStorage<DB, H>,
    key: &Key,
) -> T
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + storage::traits::StorageHasher,
{
    StorageRead::read::<T>(wl_storage, key).map_or_else(
        |err| panic!("Could not read {key}: {err:?}"),
        |value| {
            value.unwrap_or_else(|| {
                panic!(
                    "Ethereum bridge appears to be only partially configured! \
                     There was no value for {key}"
                )
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use eyre::Result;
    use namada_core::ledger::storage::testing::TestWlStorage;
    use namada_core::types::ethereum_events::EthAddress;

    use super::*;
    use crate::parameters::{
        ContractVersion, Contracts, EthereumBridgeConfig, MinimumConfirmations,
        UpgradeableContract,
    };

    /// Ensure we can serialize and deserialize a [`Config`] struct to and from
    /// TOML. This can fail if complex fields are ordered before simple fields
    /// in any of the config structs.
    #[test]
    fn test_round_trip_toml_serde() -> Result<()> {
        let config = EthereumBridgeConfig {
            erc20_whitelist: vec![],
            eth_start_height: Default::default(),
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

    #[test]
    fn test_ethereum_bridge_config_read_write_storage() {
        let mut wl_storage = TestWlStorage::default();
        let config = EthereumBridgeConfig {
            erc20_whitelist: vec![],
            eth_start_height: Default::default(),
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
        config.init_storage(&mut wl_storage);

        let read = EthereumOracleConfig::read(&wl_storage).unwrap();
        let config = EthereumOracleConfig::from(config);

        assert_eq!(config, read);
    }

    #[test]
    fn test_ethereum_bridge_config_uninitialized() {
        let wl_storage = TestWlStorage::default();
        let read = EthereumOracleConfig::read(&wl_storage);

        assert!(read.is_none());
    }

    #[test]
    #[should_panic(expected = "Could not read")]
    fn test_ethereum_bridge_config_storage_corrupt() {
        let mut wl_storage = TestWlStorage::default();
        let config = EthereumBridgeConfig {
            erc20_whitelist: vec![],
            eth_start_height: Default::default(),
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
        config.init_storage(&mut wl_storage);
        let min_confirmations_key = bridge_storage::min_confirmations_key();
        wl_storage
            .write_bytes(&min_confirmations_key, vec![42, 1, 2, 3, 4])
            .unwrap();

        // This should panic because the min_confirmations value is not valid
        EthereumOracleConfig::read(&wl_storage);
    }

    #[test]
    #[should_panic(
        expected = "Ethereum bridge appears to be only partially configured!"
    )]
    fn test_ethereum_bridge_config_storage_partially_configured() {
        let mut wl_storage = TestWlStorage::default();
        wl_storage
            .write_bytes(
                &bridge_storage::active_key(),
                encode(&EthBridgeStatus::Enabled(EthBridgeEnabled::AtGenesis)),
            )
            .unwrap();
        // Write a valid min_confirmations value
        wl_storage
            .write_bytes(
                &bridge_storage::min_confirmations_key(),
                MinimumConfirmations::default().try_to_vec().unwrap(),
            )
            .unwrap();

        // This should panic as the other config values are not written
        EthereumOracleConfig::read(&wl_storage);
    }
}
