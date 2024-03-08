//! Types that are used in validity predicates.

use thiserror::Error;

use crate::borsh::{BorshDeserialize, BorshSerialize};

/// Helper trait for converting between result types.
pub trait VpErrorExtResult<T> {
    /// Convert to a [`Result`] with [`VpError`] errors.
    fn into_vp_error(self) -> Result<T, VpError>;
}

impl<T, E> VpErrorExtResult<T> for Result<T, E>
where
    E: core::fmt::Display,
{
    #[inline]
    fn into_vp_error(self) -> Result<T, VpError> {
        self.map_err(|err| VpError::Erased(err.to_string()))
    }
}

/// Error result returned by validity predicates.
#[allow(missing_docs)]
#[derive(Debug, Error, BorshSerialize, BorshDeserialize)]
pub enum VpError {
    #[error("Transaction rejected")]
    Unspecified,
    #[error("Gas limit exceeded")]
    OutOfGas,
    #[error("Found invalid transaction signature")]
    InvalidSignature,
    #[error("{0}")]
    Erased(String), // type erased error
}
