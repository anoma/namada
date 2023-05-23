use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};

use super::super::cli::onchain::ProposalVote;
use super::proposal::ProposalType;
use crate::ledger::governance::utils::VotePower;
use crate::types::address::Address;
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
    PGFPayment,
    /// A vote for ETH bridge carrying the signature over the proposed message
    ETHBridge(Signature),
}

/// The storage vote wrapper for governance proposals
#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize, Eq)]
pub struct StorageVoteWrapper {
    pub vote: StorageVote,
    pub voting_power: VotePower,
    pub delegator: Option<Address>
}

#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize, Eq)]
/// The vote for a proposal
pub enum StorageVote {
    /// Yes
    Yay(VoteType),
    /// No
    Nay,
}

impl StorageVote {
    /// Check if a vote is yay
    pub fn is_yay(&self) -> bool {
        matches!(self, Self::Yay(_))
    }

    /// Check if vote is of type default
    pub fn is_default_vote(&self) -> bool {
        matches!(
            self,
            Self::Yay(VoteType::Default)
                | Self::Nay
        )
    }

    /// Check if a vote is compatible with a proposal
    pub fn is_compatible(&self, proposal_type: &ProposalType) -> bool {
        match self {
            Self::Yay(vote_type) => proposal_type.eq(vote_type),
            Self::Nay => true,
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
                Some(Self::Yay(VoteType::Default))
            }
            (ProposalVote::Yay, ProposalType::PGFSteward(_)) => {
                Some(Self::Yay(VoteType::PGFSteward))
            }
            (ProposalVote::Yay, ProposalType::PGFPayment(_)) => {
                Some(Self::Yay(VoteType::PGFPayment))
            }
            (ProposalVote::Yay, ProposalType::ETHBridge(data)) => {
                if let Some(key) = secret_key {
                    let signature = common::SigScheme::sign(&key, data);
                    Some(Self::Yay(VoteType::ETHBridge(
                        signature,
                    )))
                } else {
                    None
                }
            }
            (ProposalVote::Nay, ProposalType::Default(_)) => {
                Some(Self::Nay)
            }
            (ProposalVote::Nay, ProposalType::PGFSteward(_)) => {
                Some(Self::Nay)
            }
            (ProposalVote::Nay, ProposalType::PGFPayment(_)) => {
                Some(Self::Nay)
            }
            (ProposalVote::Nay, ProposalType::ETHBridge(_)) => {
                Some(Self::Nay)
            }
            _ => None,
        }
    }
}

impl Display for StorageVote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yay(vote_type) => match vote_type {
                VoteType::Default
                | VoteType::PGFSteward
                | VoteType::PGFPayment => write!(f, "yay"),
                VoteType::ETHBridge(sig) => {
                    write!(f, "yay with signature: {:#?}", sig)
                }
            },

            Self::Nay => write!(f, "nay"),
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
            Self::ETHBridge(_) => {
                matches!(other, VoteType::ETHBridge(_))
            }
        }
    }
}
