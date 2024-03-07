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
        match self {
            Ok(ok) => Ok(ok),
            Err(err) => Err(err.to_string()),
        }
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

/// Sentinel used in validity predicates to signal events that require special
/// replay protection handling back to the protocol.
#[derive(Debug, Default)]
pub enum VpSentinel {
    /// No action required
    #[default]
    None,
    /// Exceeded gas limit
    OutOfGas,
    /// Found invalid transaction signature
    InvalidSignature,
}

impl VpSentinel {
    /// Check if the Vp ran out of gas
    pub fn is_out_of_gas(&self) -> bool {
        matches!(self, Self::OutOfGas)
    }

    /// Check if the Vp found an invalid signature
    pub fn is_invalid_signature(&self) -> bool {
        matches!(self, Self::InvalidSignature)
    }

    /// Set the sentinel for an out of gas error
    pub fn set_out_of_gas(&mut self) {
        *self = Self::OutOfGas
    }

    /// Set the sentinel for an invalid signature error
    pub fn set_invalid_signature(&mut self) {
        *self = Self::InvalidSignature
    }
}
