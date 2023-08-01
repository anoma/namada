use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};

use super::super::cli::onchain::ProposalVote;
use super::proposal::ProposalType;
use crate::types::key::common::{self, Signature};
use crate::types::key::SigScheme;

/// The type of a governance vote with the optional associated Memo
#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize, Eq)]
pub enum VoteType {
    /// A default vote without Memo
    Default,
    /// A vote for the PGF stewards
    PGFSteward,
    /// A vote for a PGF payment proposal
    PGFPayment
}

#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize, Eq)]
/// The vote for a proposal
pub enum StorageProposalVote {
    /// Yes
    Yay(VoteType),
    /// No
    Nay,
}

impl StorageProposalVote {
    /// Check if a vote is yay
    pub fn is_yay(&self) -> bool {
        matches!(self, StorageProposalVote::Yay(_))
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
        }
    }

    /// Create a new vote
    pub fn build(
        proposal_vote: ProposalVote,
        proposal_type: ProposalType,
        secret_key: Option<common::SecretKey>,
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
