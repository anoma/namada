use std::collections::BTreeMap;
use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::address::Address;
use namada_core::storage::Epoch;
use namada_core::token;
use serde::{Deserialize, Serialize};

use super::validation::{
    is_valid_author_balance, is_valid_content, is_valid_default_proposal_data,
    is_valid_end_epoch, is_valid_grace_epoch, is_valid_pgf_funding_data,
    is_valid_pgf_stewards_data, is_valid_proposal_period, is_valid_start_epoch,
    ProposalValidation,
};
use crate::parameters::GovernanceParameters;
use crate::storage::proposal::PGFTarget;

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
/// The proposal structure
pub struct OnChainProposal {
    /// The proposal id
    pub id: u64,
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

impl DefaultProposal {
    /// Validate a default funding proposal
    pub fn validate(
        self,
        governance_parameters: &GovernanceParameters,
        current_epoch: Epoch,
        balance: token::Amount,
        force: bool,
    ) -> Result<Self, ProposalValidation> {
        if force {
            return Ok(self);
        }
        is_valid_start_epoch(
            self.proposal.voting_start_epoch,
            current_epoch,
            governance_parameters.min_proposal_voting_period,
        )?;
        is_valid_end_epoch(
            self.proposal.voting_start_epoch,
            self.proposal.voting_end_epoch,
            current_epoch,
            governance_parameters.min_proposal_voting_period,
            governance_parameters.min_proposal_voting_period,
            governance_parameters.max_proposal_period,
        )?;
        is_valid_grace_epoch(
            self.proposal.grace_epoch,
            self.proposal.voting_end_epoch,
            governance_parameters.min_proposal_grace_epochs,
        )?;
        is_valid_proposal_period(
            self.proposal.voting_start_epoch,
            self.proposal.grace_epoch,
            governance_parameters.max_proposal_period,
        )?;
        is_valid_author_balance(
            balance,
            governance_parameters.min_proposal_fund,
        )?;
        is_valid_content(
            &self.proposal.content,
            governance_parameters.max_proposal_content_size,
        )?;
        is_valid_default_proposal_data(
            &self.data,
            governance_parameters.max_proposal_code_size,
        )?;

        Ok(self)
    }
}

impl TryFrom<&[u8]> for DefaultProposal {
    type Error = serde_json::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(value)
    }
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

impl PgfStewardProposal {
    /// Validate a Pgf stewards proposal
    pub fn validate(
        self,
        governance_parameters: &GovernanceParameters,
        current_epoch: Epoch,
        balance: token::Amount,
        force: bool,
    ) -> Result<Self, ProposalValidation> {
        if force {
            return Ok(self);
        }
        is_valid_start_epoch(
            self.proposal.voting_start_epoch,
            current_epoch,
            governance_parameters.min_proposal_voting_period,
        )?;
        is_valid_end_epoch(
            self.proposal.voting_start_epoch,
            self.proposal.voting_end_epoch,
            current_epoch,
            governance_parameters.min_proposal_voting_period,
            governance_parameters.min_proposal_voting_period,
            governance_parameters.max_proposal_period,
        )?;
        is_valid_grace_epoch(
            self.proposal.grace_epoch,
            self.proposal.voting_end_epoch,
            governance_parameters.min_proposal_grace_epochs,
        )?;
        is_valid_proposal_period(
            self.proposal.voting_start_epoch,
            self.proposal.grace_epoch,
            governance_parameters.max_proposal_period,
        )?;
        is_valid_author_balance(
            balance,
            governance_parameters.min_proposal_fund,
        )?;
        is_valid_content(
            &self.proposal.content,
            governance_parameters.max_proposal_content_size,
        )?;
        is_valid_pgf_stewards_data(&self.data, &self.proposal.author)?;

        Ok(self)
    }
}

impl TryFrom<&[u8]> for PgfStewardProposal {
    type Error = serde_json::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(value)
    }
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

impl PgfFundingProposal {
    /// Validate a Pgf funding proposal
    pub fn validate(
        self,
        governance_parameters: &GovernanceParameters,
        current_epoch: Epoch,
        force: bool,
    ) -> Result<Self, ProposalValidation> {
        if force {
            return Ok(self);
        }
        is_valid_start_epoch(
            self.proposal.voting_start_epoch,
            current_epoch,
            governance_parameters.min_proposal_voting_period,
        )?;
        is_valid_end_epoch(
            self.proposal.voting_start_epoch,
            self.proposal.voting_end_epoch,
            current_epoch,
            governance_parameters.min_proposal_voting_period,
            governance_parameters.min_proposal_voting_period,
            governance_parameters.max_proposal_period,
        )?;
        is_valid_grace_epoch(
            self.proposal.grace_epoch,
            self.proposal.voting_end_epoch,
            governance_parameters.min_proposal_grace_epochs,
        )?;
        is_valid_proposal_period(
            self.proposal.voting_start_epoch,
            self.proposal.grace_epoch,
            governance_parameters.max_proposal_period,
        )?;
        is_valid_content(
            &self.proposal.content,
            governance_parameters.max_proposal_content_size,
        )?;
        is_valid_pgf_funding_data(&self.data)?;

        Ok(self)
    }
}

impl TryFrom<&[u8]> for PgfFundingProposal {
    type Error = serde_json::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(value)
    }
}

/// Pgf stewards
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfSteward {
    /// Pgf action
    pub action: PgfAction,
    /// steward address
    pub address: Address,
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

impl PgfAction {
    /// Check if a pgf action is adding a steward
    pub fn is_add(&self) -> bool {
        matches!(self, PgfAction::Add)
    }
}

/// Pgf funding
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfFunding {
    /// Pgf continuous funding
    pub continuous: Vec<PGFTarget>,
    /// pgf retro fundings
    pub retro: Vec<PGFTarget>,
}

impl Display for PgfFunding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.continuous.is_empty() {
            write!(f, "Continuous: ")?;
            for target in &self.continuous {
                write!(f, "  {}", &target)?;
            }
        }
        if !self.retro.is_empty() {
            write!(f, "Retro: ")?;
            for target in &self.retro {
                write!(f, "  {}", &target)?;
            }
        }
        Ok(())
    }
}

/// Pgf continuous funding
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfContinuous {
    /// Pgf target
    pub target: PGFTarget,
    /// Pgf action
    pub action: PgfAction,
}

/// Pgf retro funding
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfRetro {
    /// Pgf retro target
    pub target: PGFTarget,
}
