use std::collections::BTreeMap;

use namada_core::address::Address;
use namada_core::storage::Epoch;
use namada_core::token;
use thiserror::Error;

use super::onchain::{PgfFunding, StewardsUpdate};

/// This enum raprresent a proposal data
#[derive(Clone, Debug, PartialEq, Error)]
pub enum ProposalValidation {
    /// The proposal field are correct but there is no signature
    #[error("The proposal is not signed. Can't vote on it")]
    OkNoSignature,
    /// The proposal start epoch is invalid
    #[error(
        "Invalid proposal start epoch: {0} must be greater than current epoch \
         {1} and a multiple of {2}"
    )]
    InvalidStartEpoch(Epoch, Epoch, u64),
    /// The proposal difference between start and end epoch is invalid
    #[error(
        "Invalid proposal end epoch: difference between proposal start and \
         end epoch must be at least {0}, at max {1} and the end epoch must be \
         a multiple of {0}"
    )]
    InvalidStartEndDifference(u64, u64),
    /// The proposal difference between end and grace epoch is invalid
    #[error(
        "Invalid proposal grace epoch: difference between proposal grace and \
         end epoch must be at least {0}, but found {1}"
    )]
    InvalidEndGraceDifference(u64, u64),
    /// The proposal difference between end and grace epoch is invalid
    #[error(
        "Invalid proposal period: difference between proposal start and grace \
         epoch must be at most {1}, but found {0}"
    )]
    InvalidProposalPeriod(u64, u64),
    /// The proposal author does not have enough balance to pay for proposal
    /// fees
    #[error(
        "Invalid proposal minimum funds: the author address has {0} but \
         minimum is {1}"
    )]
    InvalidBalance(String, String),
    /// The proposal content is too large
    #[error(
        "Invalid proposal content length: the proposal content length is {0} \
         but maximum is {1}"
    )]
    InvalidContentLength(u64, u64),
    /// Invalid offline proposal tally epoch
    #[error(
        "Invalid proposal tally epoch: tally epoch ({0}) must be less than \
         current epoch ({1})"
    )]
    InvalidTallyEPoch(Epoch, Epoch),
    /// The proposal wasm code is not valid
    #[error(
        "Invalid proposal extra data: file doesn't exist or content size \
         ({0}) is to big (max {1})"
    )]
    InvalidDefaultProposalExtraData(u64, u64),
    /// The pgf stewards data is not valid
    #[error("Invalid proposal extra data: cannot be empty.")]
    InvalidPgfStewardsExtraData,
    /// The pgf funding data is not valid
    #[error("invalid proposal extra data: cannot be empty.")]
    InvalidPgfFundingExtraData,
}

pub fn is_valid_author_balance(
    author_balance: token::Amount,
    min_proposal_fund: token::Amount,
) -> Result<(), ProposalValidation> {
    if author_balance.can_spend(&min_proposal_fund) {
        Ok(())
    } else {
        Err(ProposalValidation::InvalidBalance(
            author_balance.to_string_native(),
            min_proposal_fund.to_string_native(),
        ))
    }
}

pub fn is_valid_start_epoch(
    proposal_start_epoch: Epoch,
    current_epoch: Epoch,
    proposal_epoch_multiplier: u64,
) -> Result<(), ProposalValidation> {
    let start_epoch_greater_than_current = proposal_start_epoch > current_epoch;
    let start_epoch_is_multipler =
        proposal_start_epoch.0 % proposal_epoch_multiplier == 0;

    if start_epoch_greater_than_current && start_epoch_is_multipler {
        Ok(())
    } else {
        Err(ProposalValidation::InvalidStartEpoch(
            proposal_start_epoch,
            current_epoch,
            proposal_epoch_multiplier,
        ))
    }
}

pub fn is_valid_end_epoch(
    proposal_start_epoch: Epoch,
    proposal_end_epoch: Epoch,
    _current_epoch: Epoch,
    proposal_epoch_multiplier: u64,
    min_proposal_voting_period: u64,
    max_proposal_period: u64,
) -> Result<(), ProposalValidation> {
    let voting_period = proposal_end_epoch.0 - proposal_start_epoch.0;
    let end_epoch_is_multipler =
        proposal_end_epoch % proposal_epoch_multiplier == 0;
    let is_valid_voting_period = voting_period > 0
        && voting_period >= min_proposal_voting_period
        && min_proposal_voting_period <= max_proposal_period;

    if end_epoch_is_multipler && is_valid_voting_period {
        Ok(())
    } else {
        Err(ProposalValidation::InvalidStartEndDifference(
            min_proposal_voting_period,
            max_proposal_period,
        ))
    }
}

pub fn is_valid_grace_epoch(
    proposal_grace_epoch: Epoch,
    proposal_end_epoch: Epoch,
    min_proposal_grace_epoch: u64,
) -> Result<(), ProposalValidation> {
    let grace_period = proposal_grace_epoch.0 - proposal_end_epoch.0;

    if grace_period > 0 && grace_period >= min_proposal_grace_epoch {
        Ok(())
    } else {
        Err(ProposalValidation::InvalidEndGraceDifference(
            min_proposal_grace_epoch,
            grace_period,
        ))
    }
}

pub fn is_valid_proposal_period(
    proposal_start_epoch: Epoch,
    proposal_grace_epoch: Epoch,
    max_proposal_period: u64,
) -> Result<(), ProposalValidation> {
    let proposal_period = proposal_grace_epoch.0 - proposal_start_epoch.0;

    if proposal_period > 0 && proposal_period <= max_proposal_period {
        Ok(())
    } else {
        Err(ProposalValidation::InvalidProposalPeriod(
            proposal_period,
            max_proposal_period,
        ))
    }
}

pub fn is_valid_content(
    proposal_content: &BTreeMap<String, String>,
    max_content_length: u64,
) -> Result<(), ProposalValidation> {
    let proposal_content_keys_length: u64 =
        proposal_content.keys().map(|key| key.len() as u64).sum();
    let proposal_content_values_length: u64 = proposal_content
        .values()
        .map(|value| value.len() as u64)
        .sum();
    let proposal_content_length =
        proposal_content_values_length + proposal_content_keys_length;

    if proposal_content_length <= max_content_length {
        Ok(())
    } else {
        Err(ProposalValidation::InvalidContentLength(
            proposal_content_length,
            max_content_length,
        ))
    }
}

pub fn is_valid_tally_epoch(
    tally_epoch: Epoch,
    current_epoch: Epoch,
) -> Result<(), ProposalValidation> {
    if tally_epoch <= current_epoch {
        Ok(())
    } else {
        Err(ProposalValidation::InvalidTallyEPoch(
            tally_epoch,
            current_epoch,
        ))
    }
}

pub fn is_valid_default_proposal_data(
    data: &Option<Vec<u8>>,
    max_extra_data_size: u64,
) -> Result<(), ProposalValidation> {
    match data {
        Some(content) => {
            let extra_data_length = content.len() as u64;
            if extra_data_length <= max_extra_data_size {
                Ok(())
            } else {
                Err(ProposalValidation::InvalidDefaultProposalExtraData(
                    extra_data_length,
                    max_extra_data_size,
                ))
            }
        }
        None => Ok(()),
    }
}

pub fn is_valid_pgf_stewards_data(
    data: &StewardsUpdate,
    author: &Address,
) -> Result<(), ProposalValidation> {
    if data.add.is_some() || !data.remove.is_empty() {
        if data.add.is_some() {
            let steward_address = data.add.clone().unwrap();
            if steward_address.eq(author) {
                Ok(())
            } else {
                Err(ProposalValidation::InvalidPgfStewardsExtraData)
            }
        } else {
            Ok(())
        }
    } else {
        Err(ProposalValidation::InvalidPgfStewardsExtraData)
    }
}

pub fn is_valid_pgf_funding_data(
    data: &PgfFunding,
) -> Result<(), ProposalValidation> {
    if !data.continuous.is_empty() || !data.retro.is_empty() {
        Ok(())
    } else {
        Err(ProposalValidation::InvalidPgfFundingExtraData)
    }
}
