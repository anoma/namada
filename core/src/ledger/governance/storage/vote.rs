use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Eq,
    Serialize,
    Deserialize,
)]
/// The vote for a proposal
pub enum ProposalVote {
    /// Yes
    Yay,
    /// No
    Nay,
    /// Abstain
    Abstain,
}

impl ProposalVote {
    /// Check if a vote is yay
    pub fn is_yay(&self) -> bool {
        matches!(self, ProposalVote::Yay)
    }

    /// Check if a vote is nay
    pub fn is_nay(&self) -> bool {
        matches!(self, ProposalVote::Nay)
    }

    /// Check if a vote is abstain
    pub fn is_abstain(&self) -> bool {
        matches!(self, ProposalVote::Abstain)
    }
}

impl Display for ProposalVote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalVote::Yay => write!(f, "yay"),
            ProposalVote::Nay => write!(f, "nay"),
            ProposalVote::Abstain => write!(f, "abstain"),
        }
    }
}

impl TryFrom<String> for ProposalVote {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.trim().to_lowercase().as_str() {
            "yay" => Ok(ProposalVote::Yay),
            "nay" => Ok(ProposalVote::Nay),
            "abstain" => Ok(ProposalVote::Abstain),
            _ => Err("invalid vote".to_string()),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
/// Testing helpers and strategies for governance votes
pub mod testing {
    use proptest::prelude::{Just, Strategy};

    use super::*;

    /// Generate an arbitrary proposal vote
    pub fn arb_proposal_vote() -> impl Strategy<Value = ProposalVote> {
        Just(ProposalVote::Yay)
            .boxed()
            .prop_union(Just(ProposalVote::Nay).boxed())
            .or(Just(ProposalVote::Abstain).boxed())
    }
}
