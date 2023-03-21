use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::ledger::storage_api::token;
use crate::types::address::Address;

/// List of pgf counsil members
pub type PgfCounsilMembers = BTreeSet<CounsilMemberReward>;

/// A pgf counsil member with reward
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
    Serialize,
    Deserialize,
)]
pub struct CounsilMemberReward {
    /// The counsil member address
    pub address: Address,
    /// The reward expresses as percentage
    pub reward: Decimal,
}

impl CounsilMemberReward {
    /// Compute the member reward in [`token::Amount`]
    pub fn compute_reward_amount(
        &self,
        total_amount: token::Amount,
    ) -> Option<token::Amount> {
        total_amount.checked_mul(self.reward.into())
    }
}
