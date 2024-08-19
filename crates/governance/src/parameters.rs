use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::token;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_state::{StorageRead, StorageResult, StorageWrite};

use super::storage::keys as goverance_storage;

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
/// Governance parameter structure
pub struct GovernanceParameters {
    /// Minimum amount of locked funds
    pub min_proposal_fund: token::Amount,
    /// Maximum kibibyte length for proposal code
    pub max_proposal_code_size: u64,
    /// Minimum number of epochs between the proposal end epoch and start epoch
    pub min_proposal_voting_period: u64,
    /// Maximum number of epochs between the proposal start epoch and
    /// activation epoch
    pub max_proposal_period: u64,
    /// Maximum number of characters for proposal content
    pub max_proposal_content_size: u64,
    /// Minimum number of epochs between the end and activation epochs
    pub min_proposal_grace_epochs: u64,
    /// Maximum number of epochs between current epoch and start epoch
    pub max_proposal_latency: u64,
}

impl Default for GovernanceParameters {
    fn default() -> Self {
        Self {
            min_proposal_fund: token::Amount::native_whole(500),
            max_proposal_code_size: 300_000,
            min_proposal_voting_period: 3,
            max_proposal_period: 27,
            max_proposal_content_size: 10_000,
            min_proposal_grace_epochs: 6,
            max_proposal_latency: 30,
        }
    }
}

impl GovernanceParameters {
    /// Initialize governance parameters into storage
    pub fn init_storage<S>(&self, storage: &mut S) -> StorageResult<()>
    where
        S: StorageRead + StorageWrite,
    {
        let Self {
            min_proposal_fund,
            max_proposal_code_size,
            min_proposal_voting_period,
            max_proposal_period,
            max_proposal_content_size,
            min_proposal_grace_epochs,
            max_proposal_latency,
        } = self;

        let min_proposal_fund_key =
            goverance_storage::get_min_proposal_fund_key();
        storage.write(&min_proposal_fund_key, min_proposal_fund)?;

        let max_proposal_code_size_key =
            goverance_storage::get_max_proposal_code_size_key();
        storage.write(&max_proposal_code_size_key, max_proposal_code_size)?;

        let min_proposal_voting_period_key =
            goverance_storage::get_min_proposal_voting_period_key();
        storage.write(
            &min_proposal_voting_period_key,
            min_proposal_voting_period,
        )?;

        let max_proposal_period_key =
            goverance_storage::get_max_proposal_period_key();
        storage.write(&max_proposal_period_key, max_proposal_period)?;

        let max_proposal_content_size_key =
            goverance_storage::get_max_proposal_content_key();
        storage
            .write(&max_proposal_content_size_key, max_proposal_content_size)?;

        let min_proposal_grace_epochs_key =
            goverance_storage::get_min_proposal_grace_epochs_key();
        storage
            .write(&min_proposal_grace_epochs_key, min_proposal_grace_epochs)?;

        let max_proposal_latency_key =
            goverance_storage::get_max_proposal_latency_key();
        storage.write(&max_proposal_latency_key, max_proposal_latency)?;

        let counter_key = goverance_storage::get_counter_key();
        storage.write(&counter_key, u64::MIN)
    }
}
