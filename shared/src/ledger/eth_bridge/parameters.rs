//! Parameters for configuring the Ethereum bridge
use std::num::NonZeroU64;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::ledger::eth_bridge;
use crate::ledger::eth_bridge::{bridge_pool_vp, storage as bridge_storage};
use crate::ledger::storage::types::encode;
use crate::ledger::storage::{self, Storage};
use crate::types::ethereum_events::EthAddress;

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
        eth_bridge::vp::init_storage(storage);
        // Initialize the storage for the Bridge Pool VP.
        bridge_pool_vp::init_storage(storage);
    }
}
