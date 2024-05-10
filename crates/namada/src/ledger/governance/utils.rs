//! Governance utility functions

use thiserror::Error;

pub(super) enum ReadType {
    Pre,
    Post,
}

/// Proposal errors
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid validator set deserialization
    #[error("Invalid validator set")]
    InvalidValidatorSet,
    /// Invalid proposal field deserialization
    #[error("Invalid proposal {0}")]
    InvalidProposal(u64),
    /// Error during tally
    #[error("Error while tallying proposal: {0}")]
    Tally(String),
}
