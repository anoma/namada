use std::fmt::Display;

use super::parameters::GovParams;
use crate::types::governance::{Proposal, ProposalType};
use crate::types::storage::Epoch;
use crate::types::token;

/// This enum raprresent a proposal data
#[derive(Clone, Debug, PartialEq)]
pub enum GovInvariant {
    /// The proposal fields are correct
    Ok,
    /// The proposal start epoch is invalid
    InvalidStartEpoch(Epoch, Epoch, u64),
    /// The proposal difference between start and end epoch is invalid
    InvalidStartEndDifference(u64, u64),
    /// The proposal difference between end and grace epoch is invalid
    InvalidEndGraceDifference(u64),
    /// The proposal author does not have enought balance to pay for proposal
    /// fees
    InvalidBalance(token::Amount, token::Amount),
    /// The proposal content is too large
    InvalidContentLength(u64, u64),
}

impl Display for GovInvariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GovInvariant::Ok => {
                write!(f, "Proposal is valid.")
            }
            GovInvariant::InvalidStartEpoch(
                start_epoch,
                current_epoch,
                min_proposal_epochs,
            ) => {
                write!(
                    f,
                    "Invalid proposal start epoch: {} must be greater than \
                     current epoch {} and a multiple of {}",
                    start_epoch, current_epoch, min_proposal_epochs
                )
            }
            GovInvariant::InvalidStartEndDifference(
                min_proposal_epochs,
                max_proposal_epochs,
            ) => {
                write!(
                    f,
                    "Invalid proposal end epoch: difference between proposal \
                     start and end epoch must be at least {} and at max {} \
                     and end epoch must be a multiple of {}",
                    min_proposal_epochs,
                    max_proposal_epochs,
                    min_proposal_epochs
                )
            }
            GovInvariant::InvalidEndGraceDifference(min_grace_epochs) => {
                write!(
                    f,
                    "Invalid proposal grace epoch: difference between \
                     proposal grace and end epoch must be at least {}",
                    min_grace_epochs
                )
            }
            GovInvariant::InvalidBalance(balance, proposal_min_funds) => {
                write!(
                    f,
                    "Invalid proposal minimum funds: the author address has \
                     {} but minimum is {}",
                    balance, proposal_min_funds
                )
            }
            GovInvariant::InvalidContentLength(
                proposal_content_len,
                max_proposal_content_length,
            ) => {
                write!(
                    f,
                    "Invalid proposal content length: the proposal content \
                     length is {} but maximum is {}",
                    proposal_content_len, max_proposal_content_length
                )
            }
        }
    }
}

impl GovInvariant {
    /// Return if a proposal field are valid
    pub fn ok(&self) -> bool {
        matches!(self, GovInvariant::Ok)
    }
}

/// Check the proposal invariants for an onchain proposal
pub fn check_proposal_invariant(
    proposal: &Proposal,
    governance_parameters: &GovParams,
    current_epoch: Epoch,
    author_balance: token::Amount,
) -> GovInvariant {
    let common_invariants = check_offline_proposal_invariant(
        proposal,
        governance_parameters,
        current_epoch,
    );
    if !common_invariants.ok() {
        return common_invariants;
    }

    let proposal_content_len = proposal.content.len() as u64;
    if proposal_content_len > governance_parameters.max_proposal_code_size {
        GovInvariant::InvalidContentLength(
            proposal_content_len,
            governance_parameters.max_proposal_code_size,
        )
    } else if is_valid_author_balance(proposal, author_balance, &governance_parameters.min_proposal_fund)
    {
        GovInvariant::InvalidBalance(
            author_balance,
            governance_parameters.min_proposal_fund,
        )
    } else {
        GovInvariant::Ok
    }
}


fn is_valid_author_balance(proposal: &Proposal, author_balance: token::Amount, min_proposal_fund: &token::Amount) -> bool {
    if let ProposalType::PGFSteward(_) = proposal.r#type {
        true
    } else {
        author_balance.can_spend(&min_proposal_fund)
    }
}

/// Check the invariant of a offline proposal
pub fn check_offline_proposal_invariant(
    proposal: &Proposal,
    governance_parameters: &GovParams,
    current_epoch: Epoch,
) -> GovInvariant {
    if proposal.voting_start_epoch <= current_epoch
        || proposal.voting_start_epoch.0
            % governance_parameters.min_proposal_period
            != 0
    {
        GovInvariant::InvalidStartEpoch(
            proposal.voting_start_epoch,
            current_epoch,
            governance_parameters.min_proposal_period,
        )
    } else if proposal.voting_end_epoch <= proposal.voting_start_epoch
        || proposal.voting_end_epoch.0 - proposal.voting_start_epoch.0
            < governance_parameters.min_proposal_period
        || proposal.voting_end_epoch.0 - proposal.voting_start_epoch.0
            > governance_parameters.max_proposal_period
        || proposal.voting_end_epoch.0 % 3 != 0
    {
        GovInvariant::InvalidStartEndDifference(
            governance_parameters.min_proposal_period,
            governance_parameters.max_proposal_period,
        )
    } else if proposal.grace_epoch <= proposal.voting_end_epoch
        || proposal.grace_epoch.0 - proposal.voting_end_epoch.0
            < governance_parameters.min_proposal_grace_epochs
    {
        GovInvariant::InvalidEndGraceDifference(
            governance_parameters.min_proposal_grace_epochs,
        )
    } else {
        GovInvariant::Ok
    }
}
