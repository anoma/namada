//! Parameters for configuring the Ethereum bridge
use std::num::NonZeroU64;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::ledger::storage;
use namada_core::ledger::storage::types::encode;
use namada_core::ledger::storage::Storage;
use namada_core::types::ethereum_events::EthAddress;
use namada_core::ledger::storage_api::StorageRead;
use namada_core::types::storage::Key;
use serde::{Deserialize, Serialize};

use crate::{bridge_pool_vp, storage as bridge_storage, vp};

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
pub struct EthereumBridgeConfig {
    /// Minimum number of confirmations needed to trust an Ethereum branch.
    /// This must be at least one.
    pub min_confirmations: MinimumConfirmations,
    /// The addresses of the Ethereum contracts that need to be directly known
    /// by validators.
    pub contracts: Contracts,
}

impl EthereumBridgeConfig {
    /// Initialize the Ethereum bridge parameters in storage.
    ///
    /// If these parameters are initialized, the storage subspaces
    /// for the Ethereum bridge VPs are also initialized.
    pub fn init_storage<DB, H>(&self, storage: &mut Storage<DB, H>)
    where
        DB: storage::DB + for<'iter> storage::DBIter<'iter>,
        H: storage::traits::StorageHasher,
    {
        let Self {
            min_confirmations,
            contracts:
                Contracts {
                    native_erc20,
                    bridge,
                    governance,
                },
        } = self;
        let min_confirmations_key = bridge_storage::min_confirmations_key();
        let native_erc20_key = bridge_storage::native_erc20_key();
        let bridge_contract_key = bridge_storage::bridge_contract_key();
        let governance_contract_key = bridge_storage::governance_contract_key();
        storage
            .write(&min_confirmations_key, encode(min_confirmations))
            .unwrap();
        storage
            .write(&native_erc20_key, encode(native_erc20))
            .unwrap();
        storage.write(&bridge_contract_key, encode(bridge)).unwrap();
        storage
            .write(&governance_contract_key, encode(governance))
            .unwrap();
        // Initialize the storage for the Ethereum Bridge VP.
        vp::init_storage(storage);
        // Initialize the storage for the Bridge Pool VP.
        bridge_pool_vp::init_storage(storage);
    }

    /// Reads the latest [`EthereumBridgeConfig`] from storage. If it is not
    /// present, `None` will be returned - this could be the case if the bridge
    /// has not been bootstrapped yet. Panics if the storage appears to be
    /// corrupt.
    pub fn read<DB, H>(storage: &Storage<DB, H>) -> Option<Self>
    where
        DB: storage::DB + for<'iter> storage::DBIter<'iter>,
        H: storage::traits::StorageHasher,
    {
        let min_confirmations_key = bridge_storage::min_confirmations_key();
        let native_erc20_key = bridge_storage::native_erc20_key();
        let bridge_contract_key = bridge_storage::bridge_contract_key();
        let governance_contract_key = bridge_storage::governance_contract_key();

        let Some(min_confirmations) = StorageRead::read::<MinimumConfirmations>(
            storage,
            &min_confirmations_key,
        )
        .unwrap_or_else(|err| {
            panic!("Could not Borsh-deserialize {min_confirmations_key}: {err:?}")
        }) else {
            // The bridge has not been configured yet
            return None;
        };

        // These reads must succeed otherwise the storage is corrupt or a
        // read failed
        let native_erc20 = must_read_key(storage, &native_erc20_key);
        let bridge_contract = must_read_key(storage, &bridge_contract_key);
        let governance_contract =
            must_read_key(storage, &governance_contract_key);

        Some(Self {
            min_confirmations,
            contracts: Contracts {
                native_erc20,
                bridge: bridge_contract,
                governance: governance_contract,
            },
        })
    }
}

fn must_read_key<DB, H, T: BorshDeserialize>(
    storage: &Storage<DB, H>,
    key: &Key,
) -> T
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::traits::StorageHasher,
{
    StorageRead::read::<T>(storage, key).map_or_else(
        |err| panic!("Could not Borsh-deserialize {key}: {err:?}"),
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
    use namada_core::ledger::storage::testing::TestStorage;
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
        let mut storage = TestStorage::default();
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
        config.init_storage(&mut storage);

        let read = EthereumBridgeConfig::read(&storage).unwrap();

        assert_eq!(config, read);
    }

    #[test]
    fn test_ethereum_bridge_config_uninitialized() {
        let storage = TestStorage::default();
        let read = EthereumBridgeConfig::read(&storage);

        assert!(read.is_none());
    }

    #[test]
    #[should_panic(expected = "Could not Borsh-deserialize")]
    fn test_ethereum_bridge_config_storage_corrupt() {
        let mut storage = TestStorage::default();
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
        config.init_storage(&mut storage);
        let min_confirmations_key = bridge_storage::min_confirmations_key();
        storage
            .write(&min_confirmations_key, vec![42, 1, 2, 3, 4])
            .unwrap();

        // This should panic because the min_confirmations value is not valid
        EthereumBridgeConfig::read(&storage);
    }

    #[test]
    #[should_panic(
        expected = "Ethereum bridge appears to be only partially configured!"
    )]
    fn test_ethereum_bridge_config_storage_partially_configured() {
        let mut storage = TestStorage::default();
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
        // Write a valid min_confirmations value
        let min_confirmations_key = bridge_storage::min_confirmations_key();
        storage
            .write(
                &min_confirmations_key,
                MinimumConfirmations::default().try_to_vec().unwrap(),
            )
            .unwrap();

        // This should panic as the other config values are not written
        EthereumBridgeConfig::read(&storage);
    }
}
