//! Parameters for configuring the Ethereum bridge
use std::num::NonZeroU64;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::ledger::storage;
use namada_core::ledger::storage::types::encode;
use namada_core::ledger::storage::Storage;
use namada_core::types::ethereum_events::EthAddress;
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

        let (min_confirmations, _) =
            storage.read(&min_confirmations_key).unwrap_or_else(|err| {
                panic!("Could not read {min_confirmations_key}: {err:?}")
            });
        let min_confirmations = match min_confirmations {
            Some(bytes) => {
                MinimumConfirmations::try_from_slice(&bytes).unwrap()
            }
            None => return None,
        };
        let (native_erc20, _) =
            storage.read(&native_erc20_key).unwrap_or_else(|err| {
                panic!("Could not read {native_erc20_key}: {err:?}")
            });
        let native_erc20 = match native_erc20 {
            Some(bytes) => EthAddress::try_from_slice(&bytes).unwrap(),
            None => panic!(
                "Ethereum bridge appears to be only partially configured!"
            ),
        };
        let (bridge_contract, _) =
            storage.read(&bridge_contract_key).unwrap_or_else(|err| {
                panic!("Could not read {bridge_contract_key}: {err:?}")
            });
        let bridge_contract = match bridge_contract {
            Some(bytes) => UpgradeableContract::try_from_slice(&bytes).unwrap(),
            None => panic!(
                "Ethereum bridge appears to be only partially configured!"
            ),
        };
        let (governance_contract, _) = storage
            .read(&governance_contract_key)
            .unwrap_or_else(|err| {
                panic!("Could not read {governance_contract_key}: {err:?}")
            });
        let governance_contract = match governance_contract {
            Some(bytes) => UpgradeableContract::try_from_slice(&bytes).unwrap(),
            None => panic!(
                "Ethereum bridge appears to be only partially configured!"
            ),
        };
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

#[cfg(test)]
mod tests {
    use eyre::Result;
    use namada_core::types::ethereum_events::EthAddress;

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
}
