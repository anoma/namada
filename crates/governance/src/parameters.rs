use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::token;
use namada_storage::{Result, StorageRead, StorageWrite};

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
)]
/// Governance parameter structure
pub struct GovernanceParameters {
    /// Minimum amount of locked funds
    pub min_proposal_fund: token::Amount,
    /// Maximum kibibyte length for proposal code
    pub max_proposal_code_size: u64,
    /// Minimum proposal voting period in epochs
    pub min_proposal_voting_period: u64,
    /// Maximum proposal voting period in epochs
    pub max_proposal_period: u64,
    /// Maximum number of characters for proposal content
    pub max_proposal_content_size: u64,
    /// Minimum epochs between end and grace epochs
    pub min_proposal_grace_epochs: u64,
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
        }
    }
}

impl GovernanceParameters {
    /// Initialize governance parameters into storage
    pub fn init_storage<S>(&self, storage: &mut S) -> Result<()>
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

        let min_proposal_grace_epoch_key =
            goverance_storage::get_min_proposal_grace_epoch_key();
        storage
            .write(&min_proposal_grace_epoch_key, min_proposal_grace_epochs)?;

        let counter_key = goverance_storage::get_counter_key();
        storage.write(&counter_key, u64::MIN)
    }
}
