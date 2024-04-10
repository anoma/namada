//! IBC system parameters

use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::token::Amount;
use namada_state::{StorageResult, StorageWrite};

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
/// Governance parameter structure
pub struct IbcParameters {
    /// Default supply limit of each token
    pub default_mint_limit: Amount,
    /// Default per-epoch throughput limit of each token
    pub default_per_epoch_throughput_limit: Amount,
}

impl Default for IbcParameters {
    fn default() -> Self {
        Self {
            default_mint_limit: Amount::zero(),
            default_per_epoch_throughput_limit: Amount::zero(),
        }
    }
}

impl IbcParameters {
    /// Initialize IBC parameters into storage
    pub fn init_storage<S>(&self, storage: &mut S) -> StorageResult<()>
    where
        S: StorageWrite,
    {
        let key = crate::storage::params_key();
        storage.write(&key, self)
    }
}
