use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::fs;

use super::onchain::{PgfFunding, PgfSteward};
use crate::proto::SignatureIndex;
use crate::types::storage::Epoch;
use crate::types::token;

/// This enum raprresent a proposal data
#[derive(Clone, Debug, PartialEq)]
pub enum ProposalValidation {
    /// The proposal fields are correct
    Ok,
    /// The proposal field are correct but there is no signature
    OkNoSignature,
    /// The proposal start epoch is invalid
    InvalidStartEpoch(Epoch, Epoch, u64),
    /// The proposal difference between start and end epoch is invalid
    InvalidStartEndDifference(u64, u64),
    /// The proposal difference between end and grace epoch is invalid
    InvalidEndGraceDifference(u64, u64),
    /// The proposal author does not have enought balance to pay for proposal
    /// fees
    InvalidBalance(token::Amount, token::Amount),
    /// The proposal content is too large
    InvalidContentLength(u64, u64),
    /// Invalid offline proposal tally epoch
    InvalidTallyEPoch(Epoch, Epoch),
    /// The proposal wasm code is not valid
    InvalidDefaultProposalExtraData(u64, u64),
    /// The eth proposal data is not valid
    InvalidEthProposalExtraData(u64, u64),
    /// The pgf stewards data is not valid
    InvalidPgfStewardsExtraData,
    /// The pgf funding data is not valid
    InvalidPgfFundingExtraData,
}

impl Display for ProposalValidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalValidation::Ok => {
                write!(f, "Proposal is valid.")
            }
            ProposalValidation::InvalidStartEpoch(
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
            ProposalValidation::InvalidStartEndDifference(
                min_proposal_epochs,
                max_proposal_epochs,
            ) => {
                write!(
                    f,
                    "Invalid proposal end epoch: difference between proposal \
                     start and end epoch must be at least {}, at max {} and \
                     the end epoch must be a multiple of {}",
                    min_proposal_epochs,
                    max_proposal_epochs,
                    min_proposal_epochs
                )
            }
            ProposalValidation::InvalidEndGraceDifference(
                proposal_diff,
                min_grace_epochs,
            ) => {
                write!(
                    f,
                    "Invalid proposal grace epoch: difference between \
                     proposal grace and end epoch must be at least {}, but \
                     found {}",
                    min_grace_epochs, proposal_diff
                )
            }
            ProposalValidation::InvalidBalance(balance, proposal_min_funds) => {
                write!(
                    f,
                    "Invalid proposal minimum funds: the author address has \
                     {} but minimum is {}",
                    balance, proposal_min_funds
                )
            }
            ProposalValidation::InvalidContentLength(
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
            ProposalValidation::InvalidDefaultProposalExtraData(
                content_size,
                max_content_size,
            ) => {
                write!(
                    f,
                    "Invalid proposal extra data: file doesn't exist or \
                     content size ({}) is to big (max {})",
                    content_size, max_content_size
                )
            }
            ProposalValidation::InvalidEthProposalExtraData(
                content_size,
                max_content_size,
            ) => {
                write!(
                    f,
                    "Invalid proposal extra data: content size ({}) is to big \
                     (max {})",
                    content_size, max_content_size
                )
            }
            ProposalValidation::InvalidPgfStewardsExtraData => {
                write!(f, "invalid proposal extra data: cannot be empty.")
            }
            ProposalValidation::InvalidPgfFundingExtraData => {
                write!(f, "invalid proposal extra data: cannot be empty.")
            }
            ProposalValidation::InvalidTallyEPoch(
                tally_epoch,
                current_epoch,
            ) => {
                write!(
                    f,
                    "Invalid proposal tally epoch: tally epoch ({}) must be \
                     less than current epoch ({})",
                    tally_epoch, current_epoch
                )
            }
            ProposalValidation::OkNoSignature => {
                write!(f, "The proposal is not signed. Can't vote on it.")
            }
        }
    }
}

impl ProposalValidation {
    /// Return if a proposal field are valid
    pub fn ok(&self) -> bool {
        matches!(self, ProposalValidation::Ok)
    }
}

pub fn is_valid_author_balance(
    author_balance: token::Amount,
    min_proposal_fund: token::Amount,
) -> ProposalValidation {
    if author_balance.can_spend(&min_proposal_fund) {
        ProposalValidation::Ok
    } else {
        ProposalValidation::InvalidBalance(author_balance, min_proposal_fund)
    }
}

pub fn is_valid_start_epoch(
    proposal_start_epoch: Epoch,
    current_epoch: Epoch,
    proposal_epoch_multiplier: u64,
) -> ProposalValidation {
    let start_epoch_greater_than_current = proposal_start_epoch > current_epoch;
    let start_epoch_is_multipler =
        proposal_start_epoch.0 % proposal_epoch_multiplier == 0;

    if start_epoch_greater_than_current && start_epoch_is_multipler {
        ProposalValidation::Ok
    } else {
        ProposalValidation::InvalidStartEpoch(
            proposal_start_epoch,
            current_epoch,
            proposal_epoch_multiplier,
        )
    }
}

pub fn is_valid_end_epoch(
    proposal_start_epoch: Epoch,
    proposal_end_epoch: Epoch,
    _current_epoch: Epoch,
    proposal_epoch_multiplier: u64,
    min_proposal_period: u64,
    max_proposal_period: u64,
) -> ProposalValidation {
    let voting_period = proposal_end_epoch.0 - proposal_start_epoch.0;
    let end_epoch_is_multipler =
        proposal_end_epoch % proposal_epoch_multiplier == 0;
    let _is_valid_voting_period = voting_period > 0
        && voting_period >= min_proposal_period
        && min_proposal_period <= max_proposal_period;

    if end_epoch_is_multipler && end_epoch_is_multipler {
        ProposalValidation::Ok
    } else {
        ProposalValidation::InvalidStartEndDifference(
            min_proposal_period,
            max_proposal_period,
        )
    }
}

pub fn is_valid_grace_epoch(
    proposal_grace_epoch: Epoch,
    proposal_end_epoch: Epoch,
    min_proposal_grace_epoch: u64,
) -> ProposalValidation {
    let grace_period = proposal_grace_epoch.0 - proposal_end_epoch.0;

    if grace_period > 0 && grace_period >= min_proposal_grace_epoch {
        ProposalValidation::Ok
    } else {
        ProposalValidation::InvalidEndGraceDifference(
            grace_period,
            min_proposal_grace_epoch,
        )
    }
}

pub fn is_valid_content(
    proposal_content: &BTreeMap<String, String>,
    max_content_length: u64,
) -> ProposalValidation {
    let proposal_content_keys_length: u64 =
        proposal_content.keys().map(|key| key.len() as u64).sum();
    let proposal_content_values_length: u64 = proposal_content
        .values()
        .map(|value| value.len() as u64)
        .sum();
    let proposal_content_length =
        proposal_content_values_length + proposal_content_keys_length;

    if proposal_content_length <= max_content_length {
        ProposalValidation::Ok
    } else {
        ProposalValidation::InvalidContentLength(
            proposal_content_length,
            max_content_length,
        )
    }
}

pub fn is_valid_tally_epoch(
    tally_epoch: Epoch,
    current_epoch: Epoch,
) -> ProposalValidation {
    if tally_epoch <= current_epoch {
        ProposalValidation::Ok
    } else {
        ProposalValidation::InvalidTallyEPoch(tally_epoch, current_epoch)
    }
}

pub fn is_signable(
    signatures: BTreeSet<SignatureIndex>,
    threshold: u64,
) -> ProposalValidation {
    if signatures.len() as u64 >= threshold {
        ProposalValidation::Ok
    } else {
        ProposalValidation::OkNoSignature
    }
}

pub fn is_valid_default_proposal_data(
    data: &Option<String>,
    max_extra_data_size: u64,
) -> ProposalValidation {
    match data {
        Some(path) => {
            if let Ok(content) = fs::read(path) {
                let extra_data_length = content.len() as u64;
                if content.len() as u64 <= max_extra_data_size {
                    ProposalValidation::Ok
                } else {
                    ProposalValidation::InvalidDefaultProposalExtraData(
                        extra_data_length,
                        max_extra_data_size,
                    )
                }
            } else {
                ProposalValidation::InvalidDefaultProposalExtraData(
                    0,
                    max_extra_data_size,
                )
            }
        }
        None => ProposalValidation::Ok,
    }
}

pub fn is_valid_eth_proposal_data(
    data: &String,
    max_extra_data_size: u64,
) -> ProposalValidation {
    let data_len = data.len() as u64;
    if data_len <= max_extra_data_size {
        ProposalValidation::Ok
    } else {
        ProposalValidation::InvalidEthProposalExtraData(
            data_len,
            max_extra_data_size,
        )
    }
}

pub fn is_valid_pgf_stewards_data(
    data: &Vec<PgfSteward>,
) -> ProposalValidation {
    if !data.is_empty() {
        ProposalValidation::Ok
    } else {
        ProposalValidation::InvalidPgfStewardsExtraData
    }
}

pub fn is_valid_pgf_funding_data(data: &PgfFunding) -> ProposalValidation {
    if !data.continous.is_empty() || !data.retro.is_empty() {
        ProposalValidation::Ok
    } else {
        ProposalValidation::InvalidPgfFundingExtraData
    }
}
