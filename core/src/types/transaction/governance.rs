use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::address::Address;
use crate::types::governance::{Proposal, ProposalError, ProposalVote};
use crate::types::storage::Epoch;

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

impl TryFrom<Proposal> for (InitProposalData, Vec<u8>) {
    type Error = ProposalError;

    fn try_from(proposal: Proposal) -> Result<Self, Self::Error> {
        let proposal_code = if let Some(path) = proposal.proposal_code_path {
            match std::fs::read(path) {
                Ok(bytes) => bytes,
                Err(_) => return Err(Self::Error::InvalidProposalData),
            }
        } else {
            vec![]
        };

        Ok((
            InitProposalData {
                id: proposal.id,
                content: proposal.content.try_to_vec().unwrap(),
                author: proposal.author,
                voting_start_epoch: proposal.voting_start_epoch,
                voting_end_epoch: proposal.voting_end_epoch,
                grace_epoch: proposal.grace_epoch,
            },
            proposal_code,
        ))
    }
}
