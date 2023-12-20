use std::collections::{BTreeMap, HashSet};
use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::types::address::Address;
use namada_core::types::hash::Hash;
use namada_core::types::storage::Epoch;
use namada_core::types::token;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cli::onchain::{
    PgfAction, PgfContinous, PgfRetro, PgfSteward, StewardsUpdate,
};
use crate::utils::{ProposalStatus, TallyType};

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
