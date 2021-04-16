//! Implements transparent addresses as described in [Accounts
//! Addresses](tech-specs/src/explore/design/ledger/accounts.md#addresses).

use bech32::{self, FromBase32, ToBase32, Variant};
use nonempty::NonEmpty;
use sparse_merkle_tree::H256;
use std::{
    collections::HashSet,
    convert::TryInto,
    fmt::{Debug, Display},
    hash::Hash,
    iter::FromIterator,
    str::FromStr,
};
use thiserror::Error;

use super::Hash256;

const MAX_RAW_ADDRESS_LEN: usize = 255;
const MIN_RAW_ADDRESS_LEN: usize = 3;
const MAX_LABEL_LEN: usize = 64;

const HASH_LEN: usize = 32;
/// human-readable part of Bech32m encoded address
const ADDRESS_HRP: &str = "a";
const ADDRESS_BECH32_VARIANT: bech32::Variant = Variant::Bech32m;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Address must be at least {MIN_RAW_ADDRESS_LEN} characters long")]
    AddressTooShort,
    #[error("Address must be at most {MAX_RAW_ADDRESS_LEN} characters long")]
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
    #[error("Error decoding address from Bech32m: {0}")]
    DecodeBech32(bech32::Error),
    #[error("Error decoding address from base32: {0}")]
    DecodeBase32(bech32::Error),
    #[error(
        "Unexpected Bech32m human-readable part {0}, expected {ADDRESS_HRP}"
    )]
    UnexpectedBech32Prefix(String),
    #[error(
        "Unexpected Bech32m variant {0:?}, expected {ADDRESS_BECH32_VARIANT:?}"
    )]
    UnexpectedBech32Variant(bech32::Variant),
    #[error("Unexpected address hash length {0}, expected {HASH_LEN}")]
    UnexpectedHashLength(usize),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    pub hash: H256,
    // TODO add raw for "dev"
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RawAddress {
    pub raw: String,
    labels: NonEmpty<Label>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Label(String);

impl Address {
    pub fn root() -> Self {
        Self { hash: H256::zero() }
    }

    /// Encode the hash of the given address as a Bech32m [`String`].
    pub fn encode(&self) -> String {
        let bytes: [u8; HASH_LEN] = self.hash.into();
        bech32::encode(ADDRESS_HRP, bytes.to_base32(), ADDRESS_BECH32_VARIANT)
            .expect(&format!(
                "The human-readable part {} should never cause failure",
                ADDRESS_HRP
            ))
    }

    /// Decode an address from a hexadecimal [`String`] of its hash.
    pub fn decode(string: impl AsRef<str>) -> Result<Self> {
        let (prefix, hash_base32, variant) =
            bech32::decode(string.as_ref()).map_err(Error::DecodeBech32)?;
        if prefix != ADDRESS_HRP {
            return Err(Error::UnexpectedBech32Prefix(prefix));
        }
        match variant {
            ADDRESS_BECH32_VARIANT => {}
            _ => return Err(Error::UnexpectedBech32Variant(variant)),
        }
        let hash: Vec<u8> = FromBase32::from_base32(&hash_base32)
            .map_err(Error::DecodeBase32)?;
        let hash_len = hash.len();
        let hash: [u8; HASH_LEN] = hash
            .try_into()
            .or(Err(Error::UnexpectedHashLength(hash_len)))?;
        Ok(Self {
            hash: H256::from(hash),
        })
    }
}

impl From<H256> for Address {
    fn from(hash: H256) -> Self {
        Self { hash }
    }
}

impl RawAddress {
    pub fn hash(&self) -> Address {
        Address {
            hash: self.hash256(),
        }
    }

    pub fn parent_raw(&self) -> Option<Self> {
        NonEmpty::from_vec(self.labels.tail.clone()).map(|labels| {
            let raw = labels_to_str(&labels);
            Self { raw, labels }
        })
    }

    #[allow(dead_code)]
    pub fn parent(&self) -> Address {
        self.parent_raw()
            .map(|p| p.hash())
            .unwrap_or(Address::root())
    }
}

fn labels_to_str(labels: &NonEmpty<Label>) -> String {
    labels
        .iter()
        .map(|l| l.0.clone())
        .collect::<Vec<String>>()
        .join(".")
}

impl Hash for Address {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state)
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl Hash256 for Address {
    fn hash256(&self) -> H256 {
        self.hash.clone()
    }
}

impl Hash256 for RawAddress {
    fn hash256(&self) -> H256 {
        self.raw.hash256()
    }
}

impl FromStr for RawAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() < MIN_RAW_ADDRESS_LEN {
            return Err(Error::AddressTooShort);
        }
        if s.len() > MAX_RAW_ADDRESS_LEN {
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
        Ok(RawAddress { raw, labels })
    }
}

impl Display for RawAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
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

impl<'a> FromIterator<&'a Address> for HashSet<Address> {
    fn from_iter<T: IntoIterator<Item = &'a Address>>(iter: T) -> Self {
        let mut set = HashSet::new();
        for addr in iter {
            set.insert(addr.clone());
        }
        set
    }
}
