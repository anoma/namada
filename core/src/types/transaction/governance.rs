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
use crate::ledger::governance::storage::vote::ProposalVote;
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
    pub id: u64,
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
    pub vote: ProposalVote,
    /// The proposal author address
    pub voter: Address,
    /// Delegator addresses
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
        let continuous_fundings = value
            .data
            .continuous
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

        let extra_data = [continuous_fundings, retro_fundings].concat();

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

#[cfg(any(test, feature = "testing"))]
/// Tests and strategies for governance
pub mod tests {
    use proptest::{collection, prop_compose};

    use super::*;
    use crate::ledger::governance::storage::proposal::testing::arb_proposal_type;
    use crate::ledger::governance::storage::vote::testing::arb_proposal_vote;
    use crate::types::address::testing::arb_non_internal_address;
    use crate::types::hash::testing::arb_hash;
    use crate::types::storage::testing::arb_epoch;

    prop_compose! {
        /// Generate a proposal initialization
        pub fn arb_init_proposal()(
            id: u64,
            content in arb_hash(),
            author in arb_non_internal_address(),
            r#type in arb_proposal_type(),
            voting_start_epoch in arb_epoch(),
            voting_end_epoch in arb_epoch(),
            grace_epoch in arb_epoch(),
        ) -> InitProposalData {
            InitProposalData {
                id,
                content,
                author,
                r#type,
                voting_start_epoch,
                voting_end_epoch,
                grace_epoch,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary vote proposal
        pub fn arb_vote_proposal()(
            id: u64,
            vote in arb_proposal_vote(),
            voter in arb_non_internal_address(),
            delegations in collection::vec(arb_non_internal_address(), 0..10),
        ) -> VoteProposalData {
            VoteProposalData {
                id,
                vote,
                voter,
                delegations,
            }
        }
    }
}
