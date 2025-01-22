//! IBC system parameters

use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::token::Amount;
use namada_state::{Result, StorageWrite};

#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
/// Governance parameter structure
pub struct IbcParameters {
    /// Default rate limits for IBC tokens
    pub default_rate_limits: IbcTokenRateLimits,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
/// IBC rate limits for a token
pub struct IbcTokenRateLimits {
    /// Global mint limit for the token
    pub mint_limit: Amount,
    /// Throughput limit per epoch
    pub throughput_per_epoch_limit: Amount,
}

impl Default for IbcTokenRateLimits {
    fn default() -> Self {
        Self {
            mint_limit: Amount::zero(),
            throughput_per_epoch_limit: Amount::zero(),
        }
    }
}

impl IbcParameters {
    /// Initialize IBC parameters into storage
    pub fn init_storage<S>(&self, storage: &mut S) -> Result<()>
    where
        S: StorageWrite,
    {
        let key = crate::storage::params_key();
        storage.write(&key, self)
    }
}
