use std::collections::{BTreeMap, HashSet};
use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ledger::governance::cli::onchain::{
    PgfAction, PgfContinous, PgfRetro, PgfSteward,
};
use crate::ledger::governance::utils::{ProposalStatus, TallyType};
use crate::ledger::storage_api::token::Amount;
use crate::types::address::Address;
use crate::types::storage::Epoch;

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ProposalTypeError {
    #[error("Invalid proposal type.")]
    InvalidProposalType,
}

/// An add or remove action for PGF
#[derive(
    Debug,
    Clone,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
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
)]
pub struct PGFTarget {
    target: Address,
    amount: Amount,
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
    Default(Option<Vec<u8>>),
    /// PGF stewards proposal
    PGFSteward(HashSet<AddRemove<Address>>),
    /// PGF funding proposal
    PGFPayment(Vec<PGFAction>),
    /// ETH proposal
    ETHBridge(String),
}

impl Display for ProposalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalType::Default(_) => write!(f, "Default"),
            ProposalType::PGFSteward(_) => write!(f, "Pgf steward"),
            ProposalType::PGFPayment(_) => write!(f, "Pgf funding"),
            ProposalType::ETHBridge(_) => write!(f, "Eth"),
        }
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
    pub fn can_be_voted(
        &self,
        current_epoch: Epoch,
        is_validator: bool,
    ) -> bool {
        if is_validator {
            self.voting_start_epoch < self.voting_end_epoch
                && current_epoch * 3
                    <= self.voting_start_epoch + self.voting_end_epoch * 2
        } else {
            let valid_start_epoch = current_epoch >= self.voting_start_epoch;
            let valid_end_epoch = current_epoch <= self.voting_end_epoch;
            valid_start_epoch && valid_end_epoch
        }
    }

    pub fn get_tally_type(&self) -> TallyType {
        TallyType::from(self.r#type.clone())
    }

    pub fn get_status(&self, current_epoch: Epoch) -> ProposalStatus {
        if self.voting_start_epoch > self.voting_end_epoch {
            ProposalStatus::Pending
        } else if self.voting_start_epoch <= current_epoch
            && current_epoch <= self.voting_end_epoch
        {
            ProposalStatus::OnGoing
        } else {
            ProposalStatus::Ended
        }
    }

    pub fn to_string_with_status(&self, current_epoch: Epoch) -> String {
        format!(
            "Proposal Id: {}\n
        {:4}Type: {}\n
        {:4}Author: {}\n
        {:4}Start Epoch: {}\n
        {:4}End Epoch: {}\n
        {:4}Grace Epoch: {}\n
        {:4}Status: {}
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
            "Proposal Id: {}\n
            {:4}Type: {}\n
            {:4}Author: {}\n
            {:4}Start Epoch: {}\n
            {:4}End Epoch: {}\n
            {:4}Grace Epoch: {}
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
