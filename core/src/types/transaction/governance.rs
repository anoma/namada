use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ledger::governance::cli::onchain::{
    DefaultProposal, PgfFundingProposal, PgfStewardProposal,
};
use crate::ledger::governance::storage::proposal::{
    AddRemove, PGFAction, PGFTarget, ProposalType,
};
use crate::ledger::governance::storage::vote::StorageProposalVote;
use crate::types::address::Address;
use crate::types::hash::Hash;
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

impl InitProposalData {
    /// Get the hash of the corresponding extra data section
    pub fn get_section_code_hash(&self) -> Option<Hash> {
        match self.r#type {
            ProposalType::Default(hash) => hash,
            _ => None,
        }
    }
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
    pub vote: StorageProposalVote,
    /// The proposal author address
    pub voter: Address,
    /// Delegator addreses
    pub delegations: Vec<Address>,
}

impl TryFrom<DefaultProposal> for InitProposalData {
    type Error = ProposalError;

    fn try_from(value: DefaultProposal) -> Result<Self, Self::Error> {
        Ok(InitProposalData {
            id: value.proposal.id,
            content: Hash::default(),
            author: value.proposal.author,
            r#type: ProposalType::Default(None),
            voting_start_epoch: value.proposal.voting_start_epoch,
            voting_end_epoch: value.proposal.voting_end_epoch,
            grace_epoch: value.proposal.grace_epoch,
        })
    }
}

impl TryFrom<PgfStewardProposal> for InitProposalData {
    type Error = ProposalError;

    fn try_from(value: PgfStewardProposal) -> Result<Self, Self::Error> {
        let extra_data =
            HashSet::<AddRemove<Address>>::try_from(value.data).unwrap();

        Ok(InitProposalData {
            id: value.proposal.id,
            content: Hash::default(),
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
            .map(|funding| {
                let target = PGFTarget {
                    target: funding.address,
                    amount: funding.amount,
                };
                if funding.amount.is_zero() {
                    PGFAction::Continuous(AddRemove::Remove(target))
                } else {
                    PGFAction::Continuous(AddRemove::Add(target))
                }
            })
            .collect::<Vec<PGFAction>>();

        let retro_fundings = value
            .data
            .retro
            .iter()
            .cloned()
            .map(|funding| {
                let target = PGFTarget {
                    target: funding.address,
                    amount: funding.amount,
                };
                PGFAction::Retro(target)
            })
            .collect::<Vec<PGFAction>>();

        let extra_data = [continous_fundings, retro_fundings].concat();

        Ok(InitProposalData {
            id: value.proposal.id,
            content: Hash::default(),
            author: value.proposal.author,
            r#type: ProposalType::PGFPayment(extra_data),
            voting_start_epoch: value.proposal.voting_start_epoch,
            voting_end_epoch: value.proposal.voting_end_epoch,
            grace_epoch: value.proposal.grace_epoch,
        })
    }
}
