use borsh::{BorshDeserialize, BorshSerialize};

use super::storage as slash_fund_storage;
use crate::ledger::storage::types::encode;
use crate::ledger::storage::{self, Storage};
use crate::types::token::Amount;

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
pub struct SlashFundParams {
    /// Maximum amount of token that can be moved in a single transfer
    pub max_proposal_fund_transfer: u64,
}

impl Default for SlashFundParams {
    fn default() -> Self {
        Self {
            max_proposal_fund_transfer: 10_000,
        }
    }
}

impl SlashFundParams {
    /// Initialize slash fund parameters into storage
    pub fn init_storage<DB, H>(&self, storage: &mut Storage<DB, H>)
    where
        DB: storage::DB + for<'iter> storage::DBIter<'iter>,
        H: storage::StorageHasher,
    {
        let max_proposal_fund_transfer_key =
        slash_fund_storage::get_max_transferable_fund_key();
        let amount = Amount::whole(self.max_proposal_fund_transfer);
        storage
            .write(&max_proposal_fund_transfer_key, encode(&amount))
            .unwrap();
    }
}
