use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::validation::{
    is_valid_author_balance, is_valid_content, is_valid_default_proposal_data,
    is_valid_end_epoch, is_valid_eth_proposal_data, is_valid_grace_epoch,
    is_valid_pgf_funding_data, is_valid_pgf_stewards_data,
    is_valid_start_epoch, ProposalValidation,
};
use crate::ledger::governance::parameters::GovParams;
use crate::ledger::storage_api::token;
use crate::types::address::Address;
use crate::types::storage::Epoch;

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

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct DefaultProposal {
    /// The proposal data
    pub proposal: OnChainProposal,
    /// The default proposal extra data
    pub data: Option<String>,
}

impl DefaultProposal {
    pub fn validate(
        &self,
        governance_parameters: &GovParams,
        current_epoch: Epoch,
        balance: token::Amount,
    ) -> ProposalValidation {
        let valid_start_epoch = is_valid_start_epoch(
            self.proposal.voting_start_epoch,
            current_epoch,
            governance_parameters.min_proposal_period,
        );
        let valid_end_epoch = is_valid_end_epoch(
            self.proposal.voting_start_epoch,
            self.proposal.voting_end_epoch,
            current_epoch,
            governance_parameters.min_proposal_period,
            governance_parameters.min_proposal_period,
            governance_parameters.max_proposal_period,
        );
        let valid_grace_epoch = is_valid_grace_epoch(
            self.proposal.grace_epoch,
            self.proposal.voting_end_epoch,
            governance_parameters.min_proposal_grace_epochs,
        );
        let valid_balance = is_valid_author_balance(
            balance,
            governance_parameters.min_proposal_fund,
        );
        let valid_content = is_valid_content(
            &self.proposal.content,
            governance_parameters.max_proposal_content_size,
        );
        let valid_extra_data = is_valid_default_proposal_data(
            &self.data,
            governance_parameters.max_proposal_code_size,
        );
        if !valid_start_epoch.ok() {
            valid_start_epoch
        } else if !valid_end_epoch.ok() {
            valid_end_epoch
        } else if !valid_grace_epoch.ok() {
            valid_grace_epoch
        } else if !valid_balance.ok() {
            valid_balance
        } else if !valid_content.ok() {
            valid_content
        } else if !valid_extra_data.ok() {
            valid_extra_data
        } else {
            ProposalValidation::Ok
        }
    }
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct EthProposal {
    /// The proposal data
    pub proposal: OnChainProposal,
    /// The Eth extra data
    pub data: String,
}

impl EthProposal {
    pub fn validate(
        &self,
        governance_parameters: &GovParams,
        current_epoch: Epoch,
        balance: token::Amount,
    ) -> ProposalValidation {
        let valid_start_epoch = is_valid_start_epoch(
            self.proposal.voting_start_epoch,
            current_epoch,
            governance_parameters.min_proposal_period,
        );
        let valid_end_epoch = is_valid_end_epoch(
            self.proposal.voting_start_epoch,
            self.proposal.voting_end_epoch,
            current_epoch,
            governance_parameters.min_proposal_period,
            governance_parameters.min_proposal_period,
            governance_parameters.max_proposal_period,
        );
        let valid_grace_epoch = is_valid_grace_epoch(
            self.proposal.grace_epoch,
            self.proposal.voting_end_epoch,
            governance_parameters.min_proposal_grace_epochs,
        );
        let valid_balance = is_valid_author_balance(
            balance,
            governance_parameters.min_proposal_fund,
        );
        let valid_content = is_valid_content(
            &self.proposal.content,
            governance_parameters.max_proposal_content_size,
        );
        let valid_extra_data = is_valid_eth_proposal_data(
            &self.data,
            governance_parameters.max_proposal_code_size,
        );
        if !valid_start_epoch.ok() {
            valid_start_epoch
        } else if !valid_end_epoch.ok() {
            valid_end_epoch
        } else if !valid_grace_epoch.ok() {
            valid_grace_epoch
        } else if !valid_balance.ok() {
            valid_balance
        } else if !valid_content.ok() {
            valid_content
        } else if !valid_extra_data.ok() {
            valid_extra_data
        } else {
            ProposalValidation::Ok
        }
    }
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfStewardProposal {
    /// The proposal data
    pub proposal: OnChainProposal,
    /// The Pgf steward proposal extra data
    pub data: Vec<PgfSteward>,
}

impl PgfStewardProposal {
    pub fn validate(
        &self,
        governance_parameters: &GovParams,
        current_epoch: Epoch,
        balance: token::Amount,
    ) -> ProposalValidation {
        let valid_start_epoch = is_valid_start_epoch(
            self.proposal.voting_start_epoch,
            current_epoch,
            governance_parameters.min_proposal_period,
        );
        let valid_end_epoch = is_valid_end_epoch(
            self.proposal.voting_start_epoch,
            self.proposal.voting_end_epoch,
            current_epoch,
            governance_parameters.min_proposal_period,
            governance_parameters.min_proposal_period,
            governance_parameters.max_proposal_period,
        );
        let valid_grace_epoch = is_valid_grace_epoch(
            self.proposal.grace_epoch,
            self.proposal.voting_end_epoch,
            governance_parameters.min_proposal_grace_epochs,
        );
        let valid_balance = is_valid_author_balance(
            balance,
            governance_parameters.min_proposal_fund,
        );
        let valid_content = is_valid_content(
            &self.proposal.content,
            governance_parameters.max_proposal_content_size,
        );
        let valid_extra_data = is_valid_pgf_stewards_data(&self.data);
        if !valid_start_epoch.ok() {
            valid_start_epoch
        } else if !valid_end_epoch.ok() {
            valid_end_epoch
        } else if !valid_grace_epoch.ok() {
            valid_grace_epoch
        } else if !valid_balance.ok() {
            valid_balance
        } else if !valid_content.ok() {
            valid_content
        } else if !valid_extra_data.ok() {
            valid_extra_data
        } else {
            ProposalValidation::Ok
        }
    }
}

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
    pub fn validate(
        &self,
        governance_parameters: &GovParams,
        current_epoch: Epoch,
    ) -> ProposalValidation {
        let valid_start_epoch = is_valid_start_epoch(
            self.proposal.voting_start_epoch,
            current_epoch,
            governance_parameters.min_proposal_period,
        );
        let valid_end_epoch = is_valid_end_epoch(
            self.proposal.voting_start_epoch,
            self.proposal.voting_end_epoch,
            current_epoch,
            governance_parameters.min_proposal_period,
            governance_parameters.min_proposal_period,
            governance_parameters.max_proposal_period,
        );
        let valid_grace_epoch = is_valid_grace_epoch(
            self.proposal.grace_epoch,
            self.proposal.voting_end_epoch,
            governance_parameters.min_proposal_grace_epochs,
        );
        let valid_content = is_valid_content(
            &self.proposal.content,
            governance_parameters.max_proposal_content_size,
        );
        let valid_extra_data = is_valid_pgf_funding_data(&self.data);
        if !valid_start_epoch.ok() {
            valid_start_epoch
        } else if !valid_end_epoch.ok() {
            valid_end_epoch
        } else if !valid_grace_epoch.ok() {
            valid_grace_epoch
        } else if !valid_content.ok() {
            valid_content
        } else if !valid_extra_data.ok() {
            valid_extra_data
        } else {
            ProposalValidation::Ok
        }
    }
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfSteward {
    pub action: PgfAction,
    pub address: Address,
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub enum PgfAction {
    Add,
    Remove,
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfFunding {
    pub continous: Vec<PgfContinous>,
    pub retro: Vec<PgfRetro>,
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfContinous {
    pub target: PgfFundingTarget,
    pub action: PgfAction,
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfRetro {
    pub target: PgfFundingTarget,
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct PgfFundingTarget {
    pub amount: token::Amount,
    pub address: Address,
}

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
    Yay,
    Nay,
    Invalid,
}

impl From<String> for ProposalVote {
    fn from(vote: String) -> Self {
        match vote.trim().to_lowercase().as_str() {
            "yay" => ProposalVote::Yay,
            "nay" => ProposalVote::Nay,
            _ => ProposalVote::Invalid,
        }
    }
}

impl ProposalVote {
    pub fn is_valid(&self) -> bool {
        !self.eq(&ProposalVote::Invalid)
    }

    pub fn is_yay(&self) -> bool {
        match self {
            ProposalVote::Yay => true,
            _ => false,
        }
    }
}
