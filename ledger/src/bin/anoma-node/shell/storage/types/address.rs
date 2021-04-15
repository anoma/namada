//! Implements transparent addresses as described in [Accounts
//! Addresses](tech-specs/src/explore/design/ledger/accounts.md#addresses).

use nonempty::NonEmpty;
use sparse_merkle_tree::H256;
use std::{fmt::Display, hash::Hash, str::FromStr};
use thiserror::Error;

use super::Hash256;

const MAX_ADDRESS_LEN: usize = 255;
const MIN_ADDRESS_LEN: usize = 3;
const MAX_LABEL_LEN: usize = 64;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Address must be at least {MIN_ADDRESS_LEN} characters long")]
    AddressTooShort,
    #[error("Address must be at most {MAX_ADDRESS_LEN} characters long")]
    AddressTooLong,
    #[error("Address must not contain non-ASCII characters")]
    AddressNonAscii,
    #[error(
        "Address can only contain ASCII alphanumeric characters, hyphens and full stops"
    )]
    AddressContainsInvalidCharacter,
    #[error("Address label cannot be be empty")]
    EmptyLabel,
    #[error("Address label must be at most {MAX_LABEL_LEN} characters long")]
    LabelTooLong,
    #[error("Address label cannot begin with hyphen")]
    LabelStartsWithHyphen,
    #[error("Address label cannot end with hyphen")]
    LabelEndsWithHyphen,
    #[error("Address label cannot begin with a digit")]
    LabelStartsWithDigit,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    pub raw: String,
    labels: NonEmpty<Label>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Label(String);

impl Address {
    pub fn parent(&self) -> Option<String> {
        if self.labels.tail.is_empty() {
            return None;
        }
        Some(labels_to_str(&self.labels.tail))
    }

    pub fn parent_hash(&self) -> Option<H256> {
        self.parent().map(|p| p.hash256())
    }
}

fn labels_to_str(labels: &Vec<Label>) -> String {
    labels
        .iter()
        .map(|l| l.0.clone())
        .collect::<Vec<String>>()
        .join(".")
}

impl Hash256 for Address {
    fn hash256(&self) -> H256 {
        self.raw.hash256()
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() < MIN_ADDRESS_LEN {
            return Err(Error::AddressTooShort);
        }
        if s.len() > MAX_ADDRESS_LEN {
            return Err(Error::AddressTooLong);
        }
        if !s.is_ascii() {
            return Err(Error::AddressNonAscii);
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(Error::AddressContainsInvalidCharacter);
        }
        let raw = s.to_ascii_lowercase();
        let labels = NonEmpty::from_vec(
            raw
                .split('.')
                .map(|label| Label::from_str(label))
                .collect::<std::result::Result<Vec<_>, _>>()?,
        )
        .expect("The output of string split should never be empty, even when the source string is empty");
        Ok(Address { raw, labels })
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl Hash for Address {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.raw.hash(state)
    }
}

impl FromStr for Label {
    type Err = Error;

    /// To validate a string to be parsed properly, a [`Label`] should not be
    /// parsed directly. Instead parse the whole [`Address`].
    fn from_str(s: &str) -> Result<Self> {
        match s.chars().nth(0) {
            None => Err(Error::EmptyLabel),
            Some(first_char) => {
                if s.len() > MAX_LABEL_LEN {
                    return Err(Error::LabelTooLong);
                }
                if '-' == first_char {
                    return Err(Error::LabelStartsWithHyphen);
                }
                if first_char.is_ascii_digit() {
                    return Err(Error::LabelStartsWithDigit);
                }
                if let Some('-') = s.chars().last() {
                    return Err(Error::LabelEndsWithHyphen);
                }
                let inner = s.to_string();
                Ok(Self(inner))
            }
        }
    }
}
