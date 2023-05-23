use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ledger::governance::cli::onchain::{
    DefaultProposal, EthProposal, PgfFundingProposal, PgfStewardProposal,
};
use crate::ledger::governance::storage::proposal::{
    AddRemove, PGFAction, ProposalType,
};
use crate::ledger::governance::storage::vote::{
    StorageVote, StorageVoteWrapper,
};
use crate::ledger::governance::utils::VotePower;
use crate::types::address::Address;
use crate::types::storage::Epoch;

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ProposalError {
    #[error("Invalid proposal data.")]
    InvalidProposalData,
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
#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct VoteProposalData {
    /// The proposal id
    pub id: u64,
    /// The proposal vote
    pub vote: StorageVote,
    /// The proposal author address
    pub voter: Address,
    /// The voting power at start epoch
    pub voting_power: VotePower,
    /// Delegate address
    pub delegate: Option<Address>,
}

impl TryFrom<DefaultProposal> for InitProposalData {
    type Error = ProposalError;

    fn try_from(value: DefaultProposal) -> Result<Self, Self::Error> {
        let proposal_type = if let Some(path) = value.data {
            match std::fs::read(path) {
                Ok(code) => Ok(ProposalType::Default(Some(code))),
                Err(_) => Err(Self::Error::InvalidProposalData),
            }
        } else {
            Ok(ProposalType::Default(None))
        }?;
        let content = value
            .proposal
            .content
            .try_to_vec()
            .map_err(|_| Self::Error::InvalidProposalData)?;

        Ok(InitProposalData {
            id: value.proposal.id,
            content,
            author: value.proposal.author,
            r#type: proposal_type,
            voting_start_epoch: value.proposal.voting_start_epoch,
            voting_end_epoch: value.proposal.voting_end_epoch,
            grace_epoch: value.proposal.grace_epoch,
        })
    }
}

impl TryFrom<EthProposal> for InitProposalData {
    type Error = ProposalError;

    fn try_from(value: EthProposal) -> Result<Self, Self::Error> {
        let proposal_type = ProposalType::ETHBridge(value.data);
        let content = value
            .proposal
            .content
            .try_to_vec()
            .map_err(|_| Self::Error::InvalidProposalData)?;
        Ok(InitProposalData {
            id: value.proposal.id,
            content,
            author: value.proposal.author,
            r#type: proposal_type,
            voting_start_epoch: value.proposal.voting_start_epoch,
            voting_end_epoch: value.proposal.voting_end_epoch,
            grace_epoch: value.proposal.grace_epoch,
        })
    }
}

impl TryFrom<PgfStewardProposal> for InitProposalData {
    type Error = ProposalError;

    fn try_from(value: PgfStewardProposal) -> Result<Self, Self::Error> {
        let extra_data = value
            .data
            .iter()
            .cloned()
            .map(|steward| AddRemove::<Address>::try_from(steward).unwrap())
            .collect::<HashSet<AddRemove<Address>>>();
        let content = value
            .proposal
            .content
            .try_to_vec()
            .map_err(|_| Self::Error::InvalidProposalData)?;
        Ok(InitProposalData {
            id: value.proposal.id,
            content,
            author: value.proposal.author,
            r#type: ProposalType::PGFSteward(extra_data),
            voting_start_epoch: value.proposal.voting_start_epoch,
            voting_end_epoch: value.proposal.voting_end_epoch,
            grace_epoch: value.proposal.grace_epoch,
        })
    }
}

impl TryFrom<PgfFundingProposal> for InitProposalData {
    type Error = ProposalError;

    fn try_from(value: PgfFundingProposal) -> Result<Self, Self::Error> {
        let continous_fundings = value
            .data
            .continous
            .iter()
            .cloned()
            .map(|funding| PGFAction::try_from(funding).unwrap())
            .collect::<Vec<PGFAction>>();
        let retro_fundings = value
            .data
            .retro
            .iter()
            .cloned()
            .map(|funding| PGFAction::try_from(funding).unwrap())
            .collect::<Vec<PGFAction>>();
        let extra_data = [continous_fundings, retro_fundings].concat();
        let content = value
            .proposal
            .content
            .try_to_vec()
            .map_err(|_| Self::Error::InvalidProposalData)?;
        Ok(InitProposalData {
            id: value.proposal.id,
            content,
            author: value.proposal.author,
            r#type: ProposalType::PGFPayment(extra_data),
            voting_start_epoch: value.proposal.voting_start_epoch,
            voting_end_epoch: value.proposal.voting_end_epoch,
            grace_epoch: value.proposal.grace_epoch,
        })
    }
}

impl From<VoteProposalData> for StorageVoteWrapper {
    fn from(value: VoteProposalData) -> Self {
        Self {
            vote: value.vote,
            voting_power: value.voting_power,
            delegator: value.delegate,
        }
    }
}

/// A tx data type to create a new delegatee
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct InitDelegate {
    // The address of the delegate
    pub address: Address,
}

impl InitDelegate {
    pub fn new(address: Address) -> Self {
        Self { address }
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub enum UpdateDelegateAction {
    Add,
    Remove,
}

/// A tx data type to create a new delegatee
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct UpdateDelegate {
    // The address of the delegate
    pub delegate: Address,
    // The address of the delegator
    pub delegator: Address,
    // The action to take
    pub action: UpdateDelegateAction,
}

impl UpdateDelegate {
    pub fn new(
        delegate: Address,
        delegator: Address,
        action: UpdateDelegateAction,
    ) -> Self {
        Self {
            delegate,
            delegator,
            action,
        }
    }

    pub fn remove(delegate: Address, delegator: Address) -> Self {
        Self {
            delegate,
            delegator,
            action: UpdateDelegateAction::Remove,
        }
    }

    pub fn add(delegate: Address, delegator: Address) -> Self {
        Self {
            delegate,
            delegator,
            action: UpdateDelegateAction::Add,
        }
    }
}
