//! Chain related data types
// TODO move BlockHash and BlockHeight here from the storage types

use std::fmt::Display;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The length of chain ID string
pub const CHAIN_ID_LENGTH: usize = 30;
/// The maximum length of chain ID prefix
pub const CHAIN_ID_PREFIX_MAX_LEN: usize = 19;
/// Separator between chain ID prefix and the generated hash
pub const CHAIN_ID_PREFIX_SEP: char = ':';

/// Development default chain ID. Must be [`CHAIN_ID_LENGTH`] long.
#[cfg(feature = "dev")]
pub const DEFAULT_CHAIN_ID: &str = "anoma-devchain:000000000000000";

/// Release default chain ID. Must be [`CHAIN_ID_LENGTH`] long.
#[cfg(not(feature = "dev"))]
pub const DEFAULT_CHAIN_ID: &str = "anoma-internal:000000000000000";

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
    #[error(
        "The prefix contains forbidden characters: {0:?}. Only alphanumeric \
         or punctuation ASCII characters are allowed"
    )]
    ForbiddenCharacters(Vec<char>),
}

impl FromStr for ChainId {
    type Err = ChainIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let len = s.len();
        if len != CHAIN_ID_LENGTH {
            return Err(ChainIdParseError::UnexpectedLen(len));
        }
        let mut forbidden_chars = s
            .chars()
            .filter(|char| {
                char.is_ascii_alphanumeric() || char.is_ascii_punctuation()
            })
            .peekable();
        if forbidden_chars.next().is_some() {
            return Err(ChainIdParseError::ForbiddenCharacters(
                forbidden_chars.collect(),
            ));
        }
        Ok(Self(s.to_owned()))
    }
}

/// Chain ID prefix
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[serde(transparent)]
pub struct ChainIdPrefix(String);

impl Display for ChainIdPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ChainIdPrefix {
    /// Extracts a string slice containing the entire chain ID prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return a temporary chain ID made only from the prefix. This is not a
    /// valid chain ID and is only to be used temporarily in a network setup.
    pub fn temp_chain_id(&self) -> ChainId {
        ChainId(self.0.clone())
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ChainIdPrefixParseError {
    #[error(
        "Chain ID prefix must be up to {CHAIN_ID_PREFIX_MAX_LEN} long, got {0}"
    )]
    UnexpectedLen(usize),
    #[error(
        "The prefix contains forbidden characters: {0:?}. Only alphanumeric \
         or punctuation ASCII characters are allowed"
    )]
    ForbiddenCharacters(Vec<char>),
}

impl FromStr for ChainIdPrefix {
    type Err = ChainIdPrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let len = s.len();
        if len > CHAIN_ID_PREFIX_MAX_LEN {
            return Err(ChainIdPrefixParseError::UnexpectedLen(len));
        }
        let mut forbidden_chars = s
            .chars()
            .filter(|char| {
                !char.is_ascii_alphanumeric() && !char.is_ascii_punctuation()
            })
            .peekable();
        if forbidden_chars.next().is_some() {
            return Err(ChainIdPrefixParseError::ForbiddenCharacters(
                forbidden_chars.collect(),
            ));
        }
        Ok(Self(s.to_owned()))
    }
}
