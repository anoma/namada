use std::collections::{BTreeMap, HashSet};
use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::types::address::Address;
use namada_core::types::hash::Hash;
use namada_core::types::storage::Epoch;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::vote::StorageProposalVote;
use crate::cli::onchain::{
    DefaultProposal, PGFTarget, PgfAction, PgfContinous, PgfFundingProposal,
    PgfRetro, PgfSteward, PgfStewardProposal, StewardsUpdate,
};
use crate::utils::{ProposalStatus, TallyType};

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

/// Storage struture for pgf fundings
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct StoragePgfFunding {
    /// The data about the pgf funding
    pub detail: PGFTarget,
    /// The id of the proposal that added this funding
    pub id: u64,
}

impl StoragePgfFunding {
    /// Init a new pgf funding struct
    pub fn new(detail: PGFTarget, id: u64) -> Self {
        Self { detail, id }
    }
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
    Default(Option<Hash>),
    /// PGF stewards proposal
    PGFSteward(HashSet<AddRemove<Address>>),
    /// PGF funding proposal
    PGFPayment(Vec<PGFAction>),
}

/// An add or remove action for PGF
#[derive(
    Debug,
    Clone,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub enum AddRemove<T> {
    /// Add
    Add(T),
    /// Remove
    Remove(T),
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
    Continuous(AddRemove<PGFTarget>),
    /// A retro payment
    Retro(PGFTarget),
}

impl ProposalType {
    /// Check if the proposal type is default
    pub fn is_default(&self) -> bool {
        matches!(self, ProposalType::Default(_))
    }
}

impl Display for ProposalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalType::Default(_) => write!(f, "Default"),
            ProposalType::PGFSteward(_) => write!(f, "Pgf steward"),
            ProposalType::PGFPayment(_) => write!(f, "Pgf funding"),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ProposalTypeError {
    #[error("Invalid proposal type.")]
    InvalidProposalType,
}

impl TryFrom<StewardsUpdate> for HashSet<AddRemove<Address>> {
    type Error = ProposalTypeError;

    fn try_from(value: StewardsUpdate) -> Result<Self, Self::Error> {
        let mut data = HashSet::default();

        if value.add.is_some() {
            data.insert(AddRemove::Add(value.add.unwrap()));
        }
        for steward in value.remove {
            data.insert(AddRemove::Remove(steward));
        }
        Ok(data)
    }
}

impl TryFrom<PgfSteward> for AddRemove<Address> {
    type Error = ProposalTypeError;

    fn try_from(value: PgfSteward) -> Result<Self, Self::Error> {
        match value.action {
            PgfAction::Add => Ok(AddRemove::Add(value.address)),
            PgfAction::Remove => Ok(AddRemove::Remove(value.address)),
        }
    }
}

impl TryFrom<PgfContinous> for PGFAction {
    type Error = ProposalTypeError;

    fn try_from(value: PgfContinous) -> Result<Self, Self::Error> {
        match value.action {
            PgfAction::Add => {
                Ok(PGFAction::Continuous(AddRemove::Add(PGFTarget {
                    target: value.target.address,
                    amount: value.target.amount,
                })))
            }
            PgfAction::Remove => {
                Ok(PGFAction::Continuous(AddRemove::Remove(PGFTarget {
                    target: value.target.address,
                    amount: value.target.amount,
                })))
            }
        }
    }
}

impl TryFrom<PgfRetro> for PGFAction {
    type Error = ProposalTypeError;

    fn try_from(value: PgfRetro) -> Result<Self, Self::Error> {
        Ok(PGFAction::Retro(PGFTarget {
            target: value.target.address,
            amount: value.target.amount,
        }))
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
/// Proposal rappresentation when fetched from the storage
pub struct StorageProposal {
    /// The proposal id
    pub id: u64,
    /// The proposal content
    pub content: BTreeMap<String, String>,
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

impl StorageProposal {
    /// Check if the proposal can be voted
    pub fn can_be_voted(
        &self,
        current_epoch: Epoch,
        is_validator: bool,
    ) -> bool {
        if is_validator {
            self.voting_start_epoch <= current_epoch
                && current_epoch * 3
                    <= self.voting_start_epoch + self.voting_end_epoch * 2
        } else {
            let valid_start_epoch = current_epoch >= self.voting_start_epoch;
            let valid_end_epoch = current_epoch <= self.voting_end_epoch;
            valid_start_epoch && valid_end_epoch
        }
    }

    /// Return the type of tally for the proposal
    pub fn get_tally_type(&self, is_steward: bool) -> TallyType {
        TallyType::from(self.r#type.clone(), is_steward)
    }

    /// Return the status of a proposal
    pub fn get_status(&self, current_epoch: Epoch) -> ProposalStatus {
        if self.voting_start_epoch > current_epoch {
            ProposalStatus::Pending
        } else if self.voting_start_epoch <= current_epoch
            && current_epoch <= self.voting_end_epoch
        {
            ProposalStatus::OnGoing
        } else {
            ProposalStatus::Ended
        }
    }

    /// Serialize a proposal to string
    pub fn to_string_with_status(&self, current_epoch: Epoch) -> String {
        format!(
            "Proposal Id: {}
        {:2}Type: {}
        {:2}Author: {}
        {:2}Content: {:?}
        {:2}Start Epoch: {}
        {:2}End Epoch: {}
        {:2}Grace Epoch: {}
        {:2}Status: {}
        ",
            self.id,
            "",
            self.r#type,
            "",
            self.author,
            "",
            self.content,
            "",
            self.voting_start_epoch,
            "",
            self.voting_end_epoch,
            "",
            self.grace_epoch,
            "",
            self.get_status(current_epoch)
        )
    }
}

impl Display for StorageProposal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Proposal Id: {}
            {:2}Type: {}
            {:2}Author: {}
            {:2}Start Epoch: {}
            {:2}End Epoch: {}
            {:2}Grace Epoch: {}
            ",
            self.id,
            "",
            self.r#type,
            "",
            self.author,
            "",
            self.voting_start_epoch,
            "",
            self.voting_end_epoch,
            "",
            self.grace_epoch
        )
    }
}

#[cfg(any(test, feature = "testing"))]
/// Testing helpers and and strategies for governance proposals
pub mod testing {
    use namada_core::types::address::testing::arb_non_internal_address;
    use namada_core::types::hash::testing::arb_hash;
    use namada_core::types::storage::testing::arb_epoch;
    use namada_core::types::token::testing::arb_amount;
    use proptest::prelude::*;
    use proptest::{collection, option, prop_compose};

    use super::*;

    /// Generate an arbitrary add or removal of what's generated by the supplied
    /// strategy
    pub fn arb_add_remove<X: Strategy>(
        strategy: X,
    ) -> impl Strategy<Value = AddRemove<<X as Strategy>::Value>> {
        (0..2, strategy).prop_map(|(discriminant, val)| match discriminant {
            0 => AddRemove::Add(val),
            1 => AddRemove::Remove(val),
            _ => unreachable!(),
        })
    }

    prop_compose! {
        /// Generate an arbitrary PGF target
        pub fn arb_pgf_target()(
            target in arb_non_internal_address(),
            amount in arb_amount(),
        ) -> PGFTarget {
            PGFTarget {
                target,
                amount,
            }
        }
    }

    /// Generate an arbitrary PGF action
    pub fn arb_pgf_action() -> impl Strategy<Value = PGFAction> {
        arb_add_remove(arb_pgf_target())
            .prop_map(PGFAction::Continuous)
            .boxed()
            .prop_union(arb_pgf_target().prop_map(PGFAction::Retro).boxed())
    }

    /// Generate an arbitrary proposal type
    pub fn arb_proposal_type() -> impl Strategy<Value = ProposalType> {
        option::of(arb_hash())
            .prop_map(ProposalType::Default)
            .boxed()
            .prop_union(
                collection::hash_set(
                    arb_add_remove(arb_non_internal_address()),
                    0..10,
                )
                .prop_map(ProposalType::PGFSteward)
                .boxed(),
            )
            .or(collection::vec(arb_pgf_action(), 0..10)
                .prop_map(ProposalType::PGFPayment)
                .boxed())
    }

    prop_compose! {
        /// Generate a proposal initialization
        pub fn arb_init_proposal()(
            id: Option<u64>,
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
