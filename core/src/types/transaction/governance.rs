use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::address::Address;
use crate::types::governance::{
    self, Proposal, ProposalError, ProposalVote, VoteType,
};
use crate::types::hash::Hash;
use crate::types::storage::Epoch;

/// The type of a Proposal
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
    Default(Option<Hash>),
    /// PGF council proposal
    PGFCouncil,
    /// ETH proposal
    ETHBridge,
}

impl Display for ProposalType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProposalType::Default(_) => write!(f, "Default"),
            ProposalType::PGFCouncil => write!(f, "PGF Council"),
            ProposalType::ETHBridge => write!(f, "ETH Bridge"),
        }
    }
}

impl PartialEq<VoteType> for ProposalType {
    fn eq(&self, other: &VoteType) -> bool {
        match self {
            Self::Default(_) => {
                matches!(other, VoteType::Default)
            }
            Self::PGFCouncil => {
                matches!(other, VoteType::PGFCouncil(..))
            }
            Self::ETHBridge => {
                matches!(other, VoteType::ETHBridge(_))
            }
        }
    }
}

impl TryFrom<governance::ProposalType> for (ProposalType, Option<Vec<u8>>) {
    type Error = ProposalError;

    fn try_from(value: governance::ProposalType) -> Result<Self, Self::Error> {
        match value {
            governance::ProposalType::Default(path) => {
                if let Some(p) = path {
                    match std::fs::read(p) {
                        Ok(code) => Ok((ProposalType::Default(Some(Hash::default())), Some(code))),
                        Err(_) => Err(Self::Error::InvalidProposalData),
                    }
                } else {
                    Ok((ProposalType::Default(None), None))
                }
            }
            governance::ProposalType::PGFCouncil => Ok((ProposalType::PGFCouncil, None)),
            governance::ProposalType::ETHBridge => Ok((ProposalType::ETHBridge, None)),
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
    pub content: Hash,
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

impl TryFrom<Proposal> for (InitProposalData, Vec<u8>, Option<Vec<u8>>) {
    type Error = ProposalError;

    fn try_from(proposal: Proposal) -> Result<Self, Self::Error> {
        let (r#type, code) = proposal.r#type.try_into()?;
        Ok((InitProposalData {
            id: proposal.id,
            content: Hash::default(),
            author: proposal.author,
            r#type,
            voting_start_epoch: proposal.voting_start_epoch,
            voting_end_epoch: proposal.voting_end_epoch,
            grace_epoch: proposal.grace_epoch,
        }, proposal.content.try_to_vec().unwrap(), code))
    }
}
