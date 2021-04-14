//! Implements transparent addresses as described in [Accounts
//! Addresses](tech-specs/src/explore/design/ledger/accounts.md#addresses).

use std::str::FromStr;
use thiserror::Error;

const MAX_ADDRESS_LEN: usize = 255;
const MIN_NAME_LEN: usize = 3;
const MAX_NAME_LEN: usize = 64;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Parsing error: {0}")]
    Parse(ParseError),
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Address must be at most {MAX_ADDRESS_LEN} characters long")]
    AddressTooLong,
    #[error("Address name must be at least {MIN_NAME_LEN} characters long")]
    AddressNameTooShort,
    #[error("Address name must be at most {MAX_NAME_LEN} characters long")]
    AddressNameTooLong,
    #[error("Address name must not begin with hyphen")]
    AddressNameStartsWithHyphen,
    #[error("Address name must not end with hyphen")]
    AddressNameEndsWithHyphen,
    #[error("Address name must not begin with a digit")]
    AddressNameStartsWithDigit,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address(Vec<AddressName>);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AddressName(String);

impl FromStr for Address {
    type Err = ParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.len() > MAX_ADDRESS_LEN {
            Err(ParseError::AddressTooLong)
        } else {
            let names: std::result::Result<Vec<_>, _> = s
                .split('.')
                .map(|name| AddressName::from_str(name))
                .collect();
            names.map(Address)
        }
    }
}

impl FromStr for AddressName {
    type Err = ParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.len() < MIN_NAME_LEN {
            Err(ParseError::AddressNameTooShort)
        } else if s.len() > MAX_NAME_LEN {
            Err(ParseError::AddressNameTooLong)
        } else {
            // safe to `unwrap`, because we checked the min length
            let first_char = s.chars().nth(0).unwrap();
            if '-' == first_char {
                return Err(ParseError::AddressNameStartsWithHyphen);
            }
            if first_char.is_ascii_digit() {
                return Err(ParseError::AddressNameStartsWithDigit);
            }
            if let Some('-') = s.chars().last() {
                return Err(ParseError::AddressNameStartsWithHyphen);
            }
            let inner = s.to_string();
            Ok(Self(inner))
        }
    }
}
