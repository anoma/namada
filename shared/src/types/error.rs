//! Generic Error Type for all of the Shared Crate

use namada_core::types::storage;

/// The standard Result type that most code ought to return
pub type Result<T> = std::result::Result<T, Error>;

/// General error interface for anything that may go wrong in the shared SDK.
///
/// The general mentality should be that this error type should cover all
/// possible errors that one may face.
#[derive(Clone, Error, Debug)]
pub enum Error {
    /// Key Retrival Errors
    #[error("Key Error: {0}")]
    KeyRetrival(#[from] storage::Error),
    /// Any Other errors that are uncategorized
    #[error("{0}")]
    Other(String),
}
