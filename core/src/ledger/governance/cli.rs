use std::collections::{BTreeMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{
    de::{DeserializeOwned, Visitor},
    Deserialize, Serialize,
};

use crate::{
    ledger::storage_api::token::Amount,
    types::{address::Address, storage::Epoch},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GovernanceError {
    #[error("Error")]
    Invalid,
}

pub type Result<T> = std::result::Result<T, GovernanceError>;

trait GovernanceProposal<T: BorshDeserialize + BorshSerialize> {
    fn is_valid_proposal(&self) -> Result<()>;
}

pub type CliDefaultProposal = Proposal<DefaultExtraData>;
pub type CliEthProposal = Proposal<EthBridgeExtraData>;
pub type CliPgfStewardProposal = Proposal<PgfStewardExtraData>;
pub type CliPgfPaymentsProposal = Proposal<PgfPaymentsExtraData>;

/// The type of a governance proposal
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    PartialEq,
)]
pub enum ProposalType {
    /// A default proposal with the optional path to wasm code
    Default,
    /// A PGF stewards proposal
    PGFSteward,
    /// A PGF funding proposal with the path to the [`PGFAction`]
    PGFPayment,
    /// An ETH bridge proposal
    ETHBridge,
}

#[derive(Debug, Clone, BorshDeserialize)]
/// The proposal structure
pub struct Proposal<T: BorshDeserialize + DeserializeOwned> {
    /// The proposal id
    pub id: Option<u64>,
    /// The proposal content
    pub content: BTreeMap<String, String>,
    /// The proposal author address
    pub author: Address,
    /// The proposal type
    pub r#type: ProposalType,
    /// Extra data
    pub data: T,
    /// The epoch from which voting is allowed
    pub voting_start_epoch: Epoch,
    /// The epoch from which voting is stopped
    pub voting_end_epoch: Epoch,
    /// The epoch from which this changes are executed
    pub grace_epoch: Epoch,
}

impl<'de> Deserialize<'de> for Proposal<T> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ProposalVisitor;

        impl Visitor<'de> for ProposalVisitor {
            type Proposal;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("Expecting a valid serialized Governance proposal.")
            }

            fn visit_str<E>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v
            }
        }
    }
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct DefaultExtraData {
    path: Option<String>,
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct EthBridgeExtraData {
    message: String,
}

/// The two sets of proposed Stewards, those to add and those to remove
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct PgfStewardExtraData {
    /// The stewards to be added
    pub add: HashSet<Address>,
    /// The stewards to be removed
    pub remove: HashSet<Address>,
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
pub struct PgfPaymentsExtraData {
    /// Continous fundings
    continous: Vec<PgfContinousPayments>,
    /// Retro fundings
    retro: Vec<PgfRetroPayments>,
}

/// The description of a continous funding pgf action
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct PgfContinousPayments {
    action: PgfAction,
    target: PgfTarget,
}

/// The description of a retro funding pgf action
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct PgfRetroPayments {
    target: PgfTarget,
}

/// The actions that a PGF Steward can propose to execute with a continous funding
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub enum PgfAction {
    Add,
    Remove,
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
)]
pub struct PgfTarget {
    target: Address,
    amount: Amount,
}
