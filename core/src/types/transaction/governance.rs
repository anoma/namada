use std::fmt::Display;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::ledger::storage_api::token::Amount;
use crate::types::address::Address;
use crate::types::governance::{
    self, Proposal, ProposalError, ProposalVote, Stewards, VoteType,
};
use crate::types::storage::Epoch;

/// The target of a PGF payment
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct PGFTarget {
    target: Address,
    amount: Amount,
}

/// An add or remove action for continuous payment
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub enum ContinuousPayment {
    /// Add a new continuous target
    Add(PGFTarget),
    /// Remove a continuous target
    Remove(PGFTarget),
}

/// The actions that a PGF Steward can propose to execute
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub enum PGFAction {
    /// A continuous payment
    Continuous(ContinuousPayment),
    /// A retro payment
    Retro(PGFTarget),
}

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
    Default(Option<Vec<u8>>),
    /// PGF stewards proposal
    PGFSteward(Stewards),
    /// PGF funding proposal
    PGFPayment(Vec<PGFAction>),
    /// ETH proposal
    ETHBridge,
}

impl Display for ProposalType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProposalType::Default(_) => write!(f, "Default"),
            ProposalType::PGFSteward(_) => write!(f, "PGF Steward"),
            ProposalType::PGFPayment(_) => write!(f, "PGF Payment"),
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
            Self::PGFSteward(_) => {
                matches!(other, VoteType::PGFSteward)
            }
            Self::PGFPayment(_) => {
                matches!(other, VoteType::PGFPayment)
            }
            Self::ETHBridge => {
                matches!(other, VoteType::ETHBridge(_))
            }
        }
    }
}

impl FromStr for ProposalType {
    type Err = ProposalError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "yay" => todo!(),
            "nay" => todo!(),
            _ => todo!()
        }
    }
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
            governance::ProposalType::PGFSteward(s) => Ok(Self::PGFSteward(s)),
            governance::ProposalType::PGFPayment(p) => {
                match serde_json::from_reader(
                    std::fs::File::open(p)
                        .map_err(|_| Self::Error::InvalidProposalData)?,
                ) {
                    Ok(actions) => Ok(Self::PGFPayment(actions)),
                    Err(_) => Err(Self::Error::InvalidProposalData),
                }
            }
            governance::ProposalType::ETHBridge => Ok(Self::ETHBridge),
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
