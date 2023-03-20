//! Configuration for an oracle.
use std::num::NonZeroU64;

use borsh::BorshDeserialize;
use eyre::eyre;
use namada_core::ledger::storage::write_log::StorageModification;
use namada_core::types::ethereum_events::EthAddress;
use namada_core::types::ethereum_structs;

/// Configuration for an oracle.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Config {
    /// The minimum number of block confirmations an Ethereum block must have
    /// before it will be checked for bridge events.
    pub min_confirmations: NonZeroU64,
    /// The Ethereum address of the current bridge contract.
    pub bridge_contract: EthAddress,
    /// The Ethereum address of the current governance contract.
    pub governance_contract: EthAddress,
    /// The earliest Ethereum block from which events may be processed.
    pub start_block: ethereum_structs::BlockHeight,
    /// Updates to the whitelisted ERC20 tokens maintained by the oracle.
    pub whitelist_update: Vec<UpdateErc20>,
}

// TODO: this production Default implementation is temporary, there should be no
//  default config - initialization should always be from storage.
impl std::default::Default for Config {
    fn default() -> Self {
        Self {
            // SAFETY: we must always call NonZeroU64::new_unchecked here with a
            // value that is >= 1
            min_confirmations: unsafe { NonZeroU64::new_unchecked(100) },
            bridge_contract: EthAddress([0; 20]),
            governance_contract: EthAddress([1; 20]),
            start_block: 0.into(),
            whitelist_update: vec![],
        }
    }
}

/// An update to the whitelisted ERC20 tokens maintained by the oracle.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum UpdateErc20 {
    /// Add to the whitelist with given denomination.
    Add(EthAddress, u8),
    /// Remove from the whitelist.
    Remove(EthAddress),
}

impl TryFrom<(EthAddress, &StorageModification)> for UpdateErc20 {
    type Error = eyre::Report;

    fn try_from(
        (addr, modification): (EthAddress, &StorageModification),
    ) -> eyre::Result<Self> {
        match modification {
            StorageModification::Write { value } => Ok(Self::Add(
                addr,
                u8::try_from_slice(value).map_err(|_| {
                    eyre!(
                        "Could not deserialize value associated with an ERC20 \
                         denomination key as u8."
                    )
                })?,
            )),
            StorageModification::Delete => Ok(Self::Remove(addr)),
            _ => Err(eyre!(
                "ERC20 Denomination keys can only be written or deleted"
            )),
        }
    }
}
