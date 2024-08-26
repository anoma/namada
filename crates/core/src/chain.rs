//! Chain related data types
// TODO move BlockHash and BlockHeight here from the storage types

use std::fmt;
use std::io::{self, Read};
use std::num::NonZeroU64;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The length of the chain ID string
pub const CHAIN_ID_LENGTH: usize = 30;
/// The maximum length of chain ID prefix
pub const CHAIN_ID_PREFIX_MAX_LEN: usize = 19;
/// Separator between chain ID prefix and the generated hash
pub const CHAIN_ID_PREFIX_SEP: char = '.';

/// Configuration parameter for the upper limit on the number
/// of bytes transactions can occupy in a block proposal.
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    BorshSerialize,
    BorshDeserializer,
)]
#[repr(transparent)]
pub struct ProposalBytes {
    inner: NonZeroU64,
}

impl BorshDeserialize for ProposalBytes {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let value: u64 = BorshDeserialize::deserialize_reader(reader)?;
        Self::new(value).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "ProposalBytes value must be in the range 1 - {}",
                    Self::RAW_MAX.get()
                ),
            )
        })
    }
}

impl Serialize for ProposalBytes {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_u64(self.inner.get())
    }
}

impl<'de> Deserialize<'de> for ProposalBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ProposalBytes;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "a u64 in the range 1 - {}",
                    ProposalBytes::RAW_MAX.get()
                )
            }

            fn visit_u64<E>(self, size: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ProposalBytes::new(size).ok_or_else(|| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Unsigned(size),
                        &self,
                    )
                })
            }

            // NOTE: this is only needed because of a bug in the toml parser
            // - https://github.com/toml-rs/toml-rs/issues/256
            // - https://github.com/toml-rs/toml/issues/512
            //
            // TODO(namada#3243): switch to `toml_edit` for TOML parsing
            fn visit_i64<E>(self, size: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let max_bytes = u64::try_from(size).map_err(|_e| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Signed(size),
                        &self,
                    )
                })?;
                ProposalBytes::new(max_bytes).ok_or_else(|| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Signed(size),
                        &self,
                    )
                })
            }
        }

        deserializer.deserialize_u64(Visitor)
    }
}

impl BorshSchema for ProposalBytes {
    fn add_definitions_recursively(
        definitions: &mut std::collections::BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        let fields = borsh::schema::Fields::NamedFields(vec![(
            "inner".into(),
            u64::declaration(),
        )]);
        let definition = borsh::schema::Definition::Struct { fields };
        definitions.insert(Self::declaration(), definition);
    }

    fn declaration() -> borsh::schema::Declaration {
        std::any::type_name::<Self>().into()
    }
}

impl Default for ProposalBytes {
    #[inline]
    fn default() -> Self {
        Self {
            inner: Self::RAW_DEFAULT,
        }
    }
}

// constants
impl ProposalBytes {
    /// The upper bound of a [`ProposalBytes`] value.
    pub const MAX: ProposalBytes = ProposalBytes {
        inner: Self::RAW_MAX,
    };
    /// The (raw) default value for a [`ProposalBytes`].
    ///
    /// This value must be within the range `[1 B, RAW_MAX MiB]`.
    const RAW_DEFAULT: NonZeroU64 = Self::RAW_MAX;
    /// The (raw) upper bound of a [`ProposalBytes`] value.
    ///
    /// The maximum space a serialized Tendermint block can
    /// occupy is 100 MiB. We reserve 10 MiB for serialization
    /// overhead, evidence and header data. For P2P safety
    /// reasons (i.e. DoS protection) we hardcap the size of
    /// tx data to 6 MiB.
    const RAW_MAX: NonZeroU64 = unsafe {
        // SAFETY: We are constructing a greater than zero
        // value, so the API contract is never violated.
        NonZeroU64::new_unchecked(6 * 1024 * 1024)
    };
}

impl ProposalBytes {
    /// Return the number of bytes as a [`u64`] value.
    #[inline]
    pub const fn get(self) -> u64 {
        self.inner.get()
    }

    /// Try to construct a new [`ProposalBytes`] instance,
    /// from the given `max_bytes` value.
    ///
    /// This function will return [`None`] if `max_bytes` is not within
    /// the inclusive range of 1 to [`ProposalBytes::MAX`].
    #[inline]
    pub fn new(max_bytes: u64) -> Option<Self> {
        NonZeroU64::new(max_bytes)
            .map(|inner| Self { inner })
            .and_then(|value| {
                if value.get() > Self::RAW_MAX.get() {
                    None
                } else {
                    Some(value)
                }
            })
    }
}

/// Release default chain ID. Must be [`CHAIN_ID_LENGTH`] long.
pub const DEFAULT_CHAIN_ID: &str = "namada-internal.00000000000000";

/// Chain ID
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
)]
#[serde(transparent)]
pub struct ChainId(pub String);

impl ChainId {
    /// Extracts a string slice containing the entire chain ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Derive the chain ID from the genesis hash and release version.
    pub fn from_genesis(
        ChainIdPrefix(prefix): ChainIdPrefix,
        genesis_bytes: impl AsRef<[u8]>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(genesis_bytes);
        // less `1` for chain ID prefix separator char
        // Cannot underflow as the `prefix.len` is checked
        #[allow(clippy::arithmetic_side_effects)]
        let width = CHAIN_ID_LENGTH - 1 - prefix.len();
        // lowercase hex of the first `width` chars of the hash
        let hash = format!("{:.width$x}", hasher.finalize(), width = width,);
        let raw = format!("{}{}{}", prefix, CHAIN_ID_PREFIX_SEP, hash);
        ChainId(raw)
    }

    /// Validate that chain ID is matching the expected value derived from the
    /// genesis hash and release version.
    pub fn validate(
        &self,
        genesis_bytes: impl AsRef<[u8]>,
    ) -> Vec<ChainIdValidationError> {
        let mut errors = vec![];
        match self.0.rsplit_once(CHAIN_ID_PREFIX_SEP) {
            Some((prefix, hash)) => {
                if prefix.len() > CHAIN_ID_PREFIX_MAX_LEN {
                    errors.push(ChainIdValidationError::Prefix(
                        ChainIdPrefixParseError::UnexpectedLen(prefix.len()),
                    ))
                }
                let mut hasher = Sha256::new();
                hasher.update(genesis_bytes);
                // less `1` for chain ID prefix separator char
                // Cannot underflow as the `prefix.len` is checked
                #[allow(clippy::arithmetic_side_effects)]
                let width = CHAIN_ID_LENGTH - 1 - prefix.len();
                // lowercase hex of the first `width` chars of the hash
                let expected_hash =
                    format!("{:.width$x}", hasher.finalize(), width = width,);
                if hash != expected_hash {
                    errors.push(ChainIdValidationError::InvalidHash(
                        expected_hash,
                        hash.to_string(),
                    ));
                }
            }
            None => {
                errors.push(ChainIdValidationError::MissingSeparator);
            }
        }
        errors
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ChainIdValidationError {
    #[error(
        "The prefix separator character '{CHAIN_ID_PREFIX_SEP}' is missing"
    )]
    MissingSeparator,
    #[error("The chain ID hash is not valid, expected {0}, got {1}")]
    InvalidHash(String, String),
    #[error("Invalid prefix {0}")]
    Prefix(ChainIdPrefixParseError),
}

impl Default for ChainId {
    fn default() -> Self {
        Self(DEFAULT_CHAIN_ID.to_string())
    }
}

impl fmt::Display for ChainId {
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
        "The chain ID contains forbidden characters: {0:?}. Only alphanumeric \
         characters and `-`, `_` and `.` are allowed."
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
                !matches!(*char as u8, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.')
            })
            .peekable();
        if forbidden_chars.peek().is_some() {
            return Err(ChainIdParseError::ForbiddenCharacters(
                forbidden_chars.collect(),
            ));
        }
        Ok(Self(s.to_owned()))
    }
}

/// Chain ID prefix
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
#[serde(transparent)]
pub struct ChainIdPrefix(String);

impl fmt::Display for ChainIdPrefix {
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
        "Chain ID prefix must at least 1 and up to {CHAIN_ID_PREFIX_MAX_LEN} \
         characters long, got {0}"
    )]
    UnexpectedLen(usize),
    #[error(
        "The prefix contains forbidden characters: {0:?}. Only alphanumeric \
         characters and `-`, `_` and `.` are allowed."
    )]
    ForbiddenCharacters(Vec<char>),
}

impl FromStr for ChainIdPrefix {
    type Err = ChainIdPrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let len = s.len();
        if !(1..=CHAIN_ID_PREFIX_MAX_LEN).contains(&len) {
            return Err(ChainIdPrefixParseError::UnexpectedLen(len));
        }
        let mut forbidden_chars = s
            .chars()
            .filter(|char| {
                !matches!(*char as u8, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.')
            })
            .peekable();
        if forbidden_chars.peek().is_some() {
            return Err(ChainIdPrefixParseError::ForbiddenCharacters(
                forbidden_chars.collect(),
            ));
        }
        Ok(Self(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Test any chain ID that is generated via `from_genesis` function is valid.
        #[test]
        fn test_any_generated_chain_id_is_valid(
            prefix in proptest::string::string_regex(r#"[A-Za-z0-9\.\-_]{1,19}"#).unwrap(),
            genesis_bytes in any::<Vec<u8>>(),
        ) {
            let chain_id_prefix = ChainIdPrefix::from_str(&prefix).unwrap();
            let chain_id = ChainId::from_genesis(chain_id_prefix, &genesis_bytes);
            // There should be no validation errors
            let errors = chain_id.validate(&genesis_bytes);
            assert!(errors.is_empty(), "There should be no validation errors {:#?}", errors);
        }

        /// Test if [`ProposalBytes`] serde serialization is correct.
        #[test]
        fn test_proposal_size_serialize_roundtrip(s in 1u64..=ProposalBytes::MAX.get()) {
            let size = ProposalBytes::new(s).expect("Test failed");
            assert_eq!(size.get(), s);
            let json = serde_json::to_string(&size).expect("Test failed");
            let deserialized: ProposalBytes =
                serde_json::from_str(&json).expect("Test failed");
            assert_eq!(size, deserialized);
        }
    }
}
