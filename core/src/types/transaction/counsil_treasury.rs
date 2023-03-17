use std::collections::BTreeSet;
use rust_decimal::Decimal;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{ledger::storage_api::token, types::address::Address};

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
    pub reward: Decimal
}

impl CounsilMemberReward {
    pub fn compute_reward_amount(&self, total_amount: token::Amount) -> Option<token::Amount> {
        return total_amount.checked_mul(self.reward.into())
    }
}