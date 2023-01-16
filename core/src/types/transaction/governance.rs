use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::address::Address;
use crate::types::governance::{self, Proposal, ProposalError, ProposalVote};
use crate::types::storage::Epoch;

/// The type of a [`InitProposal`]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub enum ProposalType {
    /// Default governance proposal with the optional wasm code
    Default(Option<Vec<u8>>),
    /// PGF council proposal
    PGFCouncil,
}

impl TryFrom<governance::ProposalType> for ProposalType {
    type Error = ProposalError;
    fn try_from(value: governance::ProposalType) -> Result<Self, Self::Error> {
        match value {
            governance::ProposalType::Default(path) => {
                if let Some(p) = path {
                    match std::fs::read(p) {
                        Ok(code) => Ok(Self::Default(Some(code))),
                        Err(_) => Err(Self::Error::InvalidProposalData),
                    }
                } else {
                    Ok(Self::Default(None))
                }
            }
            governance::ProposalType::PGFCouncil => Ok(Self::PGFCouncil),
        }
    }
}

/// A tx data type to hold proposal data
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct InitProposalData {
    /// The proposal id
    pub id: Option<u64>,
    /// The proposal content
    pub content: Vec<u8>,
    /// The proposal author address
    pub author: Address,
    /// The proposal type
    pub r#type: ProposalType,
    /// The epoch from which voting is allowed
    pub voting_start_epoch: Epoch,
    /// The epoch from which voting is stopped
    pub voting_end_epoch: Epoch,
    /// The epoch from which this changes are executed
    pub grace_epoch: Epoch,
}

/// A tx data type to hold vote proposal data
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct VoteProposalData {
    /// The proposal id
    pub id: u64,
    /// The proposal vote
    pub vote: ProposalVote,
    /// The proposal author address
    pub voter: Address,
    /// Delegator addreses
    pub delegations: Vec<Address>,
}

impl TryFrom<Proposal> for InitProposalData {
    type Error = ProposalError;

    fn try_from(proposal: Proposal) -> Result<Self, Self::Error> {
        Ok(InitProposalData {
            id: proposal.id,
            content: proposal.content.try_to_vec().unwrap(),
            author: proposal.author,
            r#type: proposal.r#type.try_into()?,
            voting_start_epoch: proposal.voting_start_epoch,
            voting_end_epoch: proposal.voting_end_epoch,
            grace_epoch: proposal.grace_epoch,
        })
    }
}
