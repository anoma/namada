//! Governance proposal and voting types

use std::collections::{BTreeMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::address::Address;
use crate::types::hash::Hash;
use crate::types::storage::Epoch;
use crate::types::token;

/// Pgf default proposal
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct DefaultProposal {
    /// The proposal data
    pub proposal: OnChainProposal,
    /// The default proposal extra data
    pub data: Option<Vec<u8>>,
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
/// The proposal structure
pub struct OnChainProposal {
    /// The proposal id
    pub id: Option<u64>,
    /// The proposal content
    pub content: BTreeMap<String, String>,
    /// The proposal author address
    pub author: Address,
    /// The epoch from which voting is allowed
    pub voting_start_epoch: Epoch,
    /// The epoch from which voting is stopped
    pub voting_end_epoch: Epoch,
    /// The epoch from which this changes are executed
    pub grace_epoch: Epoch,
}

/// Pgf funding proposal
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfFundingProposal {
    /// The proposal data
    pub proposal: OnChainProposal,
    /// The Pgf funding proposal extra data
    pub data: PgfFunding,
}

/// Pgf fundings
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfFunding {
    /// Pgf continous funding
    pub continous: Vec<PgfFundingTarget>,
    /// pgf retro fundings
    pub retro: Vec<PgfFundingTarget>,
}

/// Pgf continous funding
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfContinous {
    /// Pgf target
    pub target: PgfFundingTarget,
    /// Pgf action
    pub action: PgfAction,
}

/// Pgf retro funding
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfRetro {
    /// Pgf retro target
    pub target: PgfFundingTarget,
}

/// Pgf Target
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfFundingTarget {
    /// Target amount
    pub amount: token::Amount,
    /// Target address
    pub address: Address,
}

/// Represent an proposal vote
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    PartialEq,
)]
pub enum ProposalVote {
    /// Represent an yay proposal vote
    Yay,
    /// Represent an nay proposal vote
    Nay,
    /// Represent an abstain proposal vote
    Abstain,
}

/// Pgf action
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub enum PgfAction {
    /// Add action
    Add,
    /// Remove action
    Remove,
}

/// Pgf stewards proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgfStewardProposal {
    /// The proposal data
    pub proposal: OnChainProposal,
    /// The Pgf steward proposal extra data
    pub data: StewardsUpdate,
}

/// Pgf steward proposal extra data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StewardsUpdate {
    /// The optional steward to add
    pub add: Option<Address>,
    /// The stewards to remove
    pub remove: Vec<Address>,
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

/// The target of a PGF payment
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Ord,
    Eq,
    PartialOrd,
)]
pub struct PGFTarget {
    /// The target address
    pub target: Address,
    /// The amount of token to fund the target address
    pub amount: token::Amount,
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

#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Eq,
    Serialize,
    Deserialize,
)]
/// The vote for a proposal
pub enum StorageProposalVote {
    /// Yes
    Yay(VoteType),
    /// No
    Nay,
    /// Abstain
    Abstain,
}

/// The type of a governance vote with the optional associated Memo
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Eq,
    Serialize,
    Deserialize,
)]
pub enum VoteType {
    /// A default vote without Memo
    Default,
    /// A vote for the PGF stewards
    PGFSteward,
    /// A vote for a PGF payment proposal
    PGFPayment,
}

#[cfg(any(test, feature = "testing"))]
/// Testing helpers and and strategies for governance proposals
pub mod testing {
    use proptest::prelude::*;
    use proptest::{collection, option};

    use super::*;
    use crate::types::address::testing::arb_non_internal_address;
    use crate::types::hash::testing::arb_hash;
    use crate::types::token::testing::arb_amount;

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
        /// Geerate an arbitrary vote type
        pub fn arb_vote_type()(discriminant in 0..3) -> VoteType {
            match discriminant {
                0 => VoteType::Default,
                1 => VoteType::PGFSteward,
                2 => VoteType::PGFPayment,
                _ => unreachable!(),
            }
        }
    }

    /// Generate an arbitrary proposal vote
    pub fn arb_proposal_vote() -> impl Strategy<Value = StorageProposalVote> {
        arb_vote_type()
            .prop_map(StorageProposalVote::Yay)
            .boxed()
            .prop_union(Just(StorageProposalVote::Nay).boxed())
            .or(Just(StorageProposalVote::Abstain).boxed())
    }
}
