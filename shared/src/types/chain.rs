//! Chain related data types
// TODO move BlockHash and BlockHeight here from the storage types

use std::fmt::Display;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The length of chain ID string
pub const CHAIN_ID_LENGTH: usize = 30;

/// Development default chain ID. Must be [`CHAIN_ID_LENGTH`] long.
#[cfg(feature = "dev")]
pub const DEFAULT_CHAIN_ID: &str = "anoma-devchain-000000000000000";

/// Release default chain ID. Must be [`CHAIN_ID_LENGTH`] long.
#[cfg(not(feature = "dev"))]
pub const DEFAULT_CHAIN_ID: &str = "anoma-internal-000000000000000";

/// Chain ID
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[serde(transparent)]
pub struct ChainId(String);

impl ChainId {
    /// Extracts a string slice containing the entire chain ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ChainId {
    fn default() -> Self {
        Self(DEFAULT_CHAIN_ID.to_string())
    }
}

impl Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ChainIdParseError {
    #[error("Chain ID must be {CHAIN_ID_LENGTH} long, got {0}")]
    UnexpectedLen(usize),
}

impl FromStr for ChainId {
    type Err = ChainIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let len = s.len();
        if len != CHAIN_ID_LENGTH {
            return Err(ChainIdParseError::UnexpectedLen(len));
        }
        Ok(Self(s.to_owned()))
    }
}
