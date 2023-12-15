use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::types::address::Address;
use namada_core::types::storage::Epoch;
use namada_core::types::token;
use serde::{Deserialize, Serialize};

use super::validation::{
    is_valid_author_balance, is_valid_content, is_valid_default_proposal_data,
    is_valid_end_epoch, is_valid_grace_epoch, is_valid_pgf_funding_data,
    is_valid_pgf_stewards_data, is_valid_proposal_period, is_valid_start_epoch,
    ProposalValidation,
};
use crate::parameters::GovernanceParameters;

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

impl PgfAction {
    /// Check if a pgf action is adding a steward
    pub fn is_add(&self) -> bool {
        matches!(self, PgfAction::Add)
    }
}

impl TryFrom<String> for ProposalVote {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.trim().to_lowercase().as_str() {
            "yay" => Ok(ProposalVote::Yay),
            "nay" => Ok(ProposalVote::Nay),
            "abstain" => Ok(ProposalVote::Abstain),
            _ => Err("invalid vote".to_string()),
        }
    }
}

impl ProposalVote {
    /// Check if the vote type is yay
    pub fn is_yay(&self) -> bool {
        matches!(self, ProposalVote::Yay)
    }

    /// Check if the vote type is nay
    pub fn is_nay(&self) -> bool {
        matches!(self, ProposalVote::Nay)
    }

    /// Check if the vote type is abstain
    pub fn is_abstain(&self) -> bool {
        matches!(self, ProposalVote::Abstain)
    }

    /// Check if two votes are equal
    pub fn is_same_side(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}
