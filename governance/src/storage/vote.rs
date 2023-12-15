use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::super::cli::onchain::ProposalVote;
use super::proposal::ProposalType;

impl StorageProposalVote {
    /// Check if a vote is yay
    pub fn is_yay(&self) -> bool {
        matches!(self, StorageProposalVote::Yay(_))
    }

    /// Check if a vote is nay
    pub fn is_nay(&self) -> bool {
        matches!(self, StorageProposalVote::Nay)
    }

    /// Check if a vote is abstain
    pub fn is_abstain(&self) -> bool {
        matches!(self, StorageProposalVote::Abstain)
    }

    /// Check if two votes are equal
    pub fn is_same_side(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }

    /// Check if vote is of type default
    pub fn is_default_vote(&self) -> bool {
        matches!(
            self,
            StorageProposalVote::Yay(VoteType::Default)
                | StorageProposalVote::Nay
        )
    }

    /// Check if a vote is compatible with a proposal
    pub fn is_compatible(&self, proposal_type: &ProposalType) -> bool {
        match self {
            StorageProposalVote::Yay(vote_type) => proposal_type.eq(vote_type),
            StorageProposalVote::Nay => true,
            StorageProposalVote::Abstain => true,
        }
    }

    /// Create a new vote
    pub fn build(
        proposal_vote: &ProposalVote,
        proposal_type: &ProposalType,
    ) -> Option<Self> {
        match (proposal_vote, proposal_type) {
            (ProposalVote::Yay, ProposalType::Default(_)) => {
                Some(StorageProposalVote::Yay(VoteType::Default))
            }
            (ProposalVote::Yay, ProposalType::PGFSteward(_)) => {
                Some(StorageProposalVote::Yay(VoteType::PGFSteward))
            }
            (ProposalVote::Yay, ProposalType::PGFPayment(_)) => {
                Some(StorageProposalVote::Yay(VoteType::PGFPayment))
            }
            (ProposalVote::Nay, ProposalType::Default(_)) => {
                Some(StorageProposalVote::Nay)
            }
            (ProposalVote::Nay, ProposalType::PGFSteward(_)) => {
                Some(StorageProposalVote::Nay)
            }
            (ProposalVote::Nay, ProposalType::PGFPayment(_)) => {
                Some(StorageProposalVote::Nay)
            }
            _ => None,
        }
    }
}

impl Display for StorageProposalVote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageProposalVote::Yay(vote_type) => match vote_type {
                VoteType::Default
                | VoteType::PGFSteward
                | VoteType::PGFPayment => write!(f, "yay"),
            },

            StorageProposalVote::Nay => write!(f, "nay"),
            StorageProposalVote::Abstain => write!(f, "abstain"),
        }
    }
}

impl PartialEq<VoteType> for ProposalType {
    fn eq(&self, other: &VoteType) -> bool {
        match self {
            Self::Default(_) => {
                matches!(other, VoteType::Default)
            }
            Self::PGFSteward(_) => {
                matches!(other, VoteType::PGFSteward)
            }
            Self::PGFPayment(_) => {
                matches!(other, VoteType::PGFPayment)
            }
        }
    }
}
