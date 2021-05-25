//! The key and values that may be persisted in a DB.

use std::convert::{TryFrom, TryInto};
use std::fmt::Display;

pub use address::{Address, EstablishedAddress, ImplicitAddress};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::bytes::ByteBuf;
use crate::types::key::ed25519::{Keypair, SignedTxData};

pub mod address;
pub mod intent;
pub mod internal;
pub mod key;
pub mod token;

#[derive(Error, Debug)]
pub enum Error {
    #[error("TEMPORARY error: {error}")]
    Temporary { error: String },
    #[error("Error parsing address: {0}")]
    ParseAddress(address::Error),
    #[error("Error parsing address from a storage key")]
    ParseAddressFromKey,
    #[error("Reserved prefix or string is specified: {0}")]
    InvalidKeySeg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

// TODO adjust once chain ID scheme is chosen, add `Default` impl that allocates
// this
pub const CHAIN_ID_LENGTH: usize = 20;
pub const BLOCK_HASH_LENGTH: usize = 32;

pub const KEY_SEGMENT_SEPARATOR: char = '/';
pub const RESERVED_ADDRESS_PREFIX: char = '#';
pub const VP_KEY_PREFIX: char = '?';
pub const RESERVED_VP_KEY: &str = "?";

#[derive(
    Clone,
    Copy,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Serialize,
    Deserialize,
)]
pub struct BlockHeight(pub u64);

#[derive(
    Clone,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
pub struct BlockHash(pub [u8; BLOCK_HASH_LENGTH]);

#[derive(
    Clone,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct Key {
    pub segments: Vec<DbKeySeg>,
}

impl From<DbKeySeg> for Key {
    fn from(seg: DbKeySeg) -> Self {
        Self {
            segments: vec![seg],
        }
    }
}

impl Key {
    /// Parses string and returns a key
    pub fn parse(string: String) -> Result<Self> {
        let mut segments = Vec::new();
        for s in string.split(KEY_SEGMENT_SEPARATOR) {
            segments.push(DbKeySeg::parse(s.to_owned())?);
        }
        Ok(Key { segments })
    }

    /// Returns a new key with segments of `Self` and the given segment
    pub fn push<T: KeySeg>(&self, other: &T) -> Result<Self> {
        let mut segments = self.segments.clone();
        segments.push(DbKeySeg::parse(other.to_string())?);
        Ok(Key { segments })
    }

    /// Returns a new key with segments of `Self` and the given key
    pub fn join(&self, other: &Key) -> Self {
        let mut segments = self.segments.clone();
        let mut added = other.segments.clone();
        segments.append(&mut added);
        Key { segments }
    }

    /// Returns the addresses from the key segments
    pub fn find_addresses(&self) -> Vec<Address> {
        let mut addresses = Vec::new();
        for s in &self.segments {
            match s {
                DbKeySeg::AddressSeg(addr) => addresses.push(addr.clone()),
                _ => continue,
            }
        }
        addresses
    }

    /// Returns the length
    pub fn len(&self) -> usize {
        self.to_string().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a key of the validity predicate of the given address
    /// Only this function can push "?" segment for validity predicate
    pub fn validity_predicate(addr: &Address) -> Result<Self> {
        let mut segments = Self::from(addr.to_db_key()).segments;
        segments.push(DbKeySeg::StringSeg(RESERVED_VP_KEY.to_owned()));
        Ok(Key { segments })
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = self
            .segments
            .iter()
            .map(|s| DbKeySeg::to_string(s))
            .collect::<Vec<String>>()
            .join(&KEY_SEGMENT_SEPARATOR.to_string());
        f.write_str(&key)
    }
}

// TODO use std::convert::{TryFrom, Into}?
/// Represents a segment in a path that may be used as a database key
pub trait KeySeg {
    /// Reverse of `into_string`. Convert key segment to `Self`.
    fn parse(string: String) -> Result<Self>
    where
        Self: Sized;

    /// Convert `Self` to a string.
    fn to_string(&self) -> String;

    /// Convert `Self` to a key segment. This mapping should preserve the
    /// ordering of `Self`
    fn to_db_key(&self) -> DbKeySeg;
}

#[derive(
    Clone,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum DbKeySeg {
    AddressSeg(Address),
    StringSeg(String),
}

impl KeySeg for DbKeySeg {
    fn parse(mut string: String) -> Result<Self> {
        // a separator should not included
        if string.contains(KEY_SEGMENT_SEPARATOR) {
            return Err(Error::InvalidKeySeg(string));
        }
        match string.chars().next() {
            // address hashes are prefixed with `'#'`
            Some(c) if c == RESERVED_ADDRESS_PREFIX => {
                let _ = string.remove(0);
                Address::decode(&string)
                    .map_err(Error::ParseAddress)
                    .map(DbKeySeg::AddressSeg)
            }
            // reserved for a validity predicate
            Some(c) if c == VP_KEY_PREFIX && string == RESERVED_VP_KEY => {
                Err(Error::InvalidKeySeg(string))
            }
            _ => Ok(DbKeySeg::StringSeg(string)),
        }
    }

    fn to_string(&self) -> String {
        match self {
            DbKeySeg::AddressSeg(addr) => {
                format!("{}{}", RESERVED_ADDRESS_PREFIX, addr.encode())
            }
            DbKeySeg::StringSeg(seg) => seg.to_owned(),
        }
    }

    fn to_db_key(&self) -> DbKeySeg {
        self.clone()
    }
}

impl KeySeg for String {
    fn to_string(&self) -> String {
        self.to_owned()
    }

    fn parse(string: String) -> Result<Self> {
        Ok(string)
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::StringSeg(self.clone())
    }
}

impl KeySeg for BlockHeight {
    fn parse(string: String) -> Result<Self> {
        let h = string.parse::<u64>().map_err(|e| Error::Temporary {
            error: format!("Unexpected height value {}, {}", string, e),
        })?;
        Ok(BlockHeight(h))
    }

    fn to_string(&self) -> String {
        format!("{}", self.0)
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::StringSeg(self.to_string())
    }
}
impl TryFrom<i64> for BlockHeight {
    type Error = String;

    fn try_from(value: i64) -> std::result::Result<Self, Self::Error> {
        value
            .try_into()
            .map(BlockHeight)
            .map_err(|e| format!("Unexpected height value {}, {}", value, e))
    }
}
impl BlockHeight {
    pub fn next_height(&self) -> BlockHeight {
        BlockHeight(self.0 + 1)
    }
}

impl Default for BlockHash {
    fn default() -> Self {
        Self([0; 32])
    }
}
impl TryFrom<&[u8]> for BlockHash {
    type Error = self::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != BLOCK_HASH_LENGTH {
            return Err(Error::Temporary {
                error: format!(
                    "Unexpected block hash length {}, expected {}",
                    value.len(),
                    BLOCK_HASH_LENGTH
                ),
            });
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(value);
        Ok(BlockHash(hash))
    }
}
impl TryFrom<Vec<u8>> for BlockHash {
    type Error = self::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        if value.len() != BLOCK_HASH_LENGTH {
            return Err(Error::Temporary {
                error: format!(
                    "Unexpected block hash length {}, expected {}",
                    value.len(),
                    BLOCK_HASH_LENGTH
                ),
            });
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(&value);
        Ok(BlockHash(hash))
    }
}
impl core::fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = format!("{}", ByteBuf(&self.0));
        f.debug_tuple("BlockHash").field(&hash).finish()
    }
}

impl KeySeg for Address {
    fn to_string(&self) -> String {
        format!("{}{}", RESERVED_ADDRESS_PREFIX, self.encode())
    }

    fn parse(mut seg: String) -> Result<Self> {
        match seg.chars().next() {
            Some(c) if c == RESERVED_ADDRESS_PREFIX => {
                let _ = seg.remove(0);
                Address::decode(seg).map_err(Error::ParseAddress)
            }
            _ => Err(Error::ParseAddressFromKey),
        }
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::AddressSeg(self.clone())
    }
}

/// A tx data type to update an account's validity predicate
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct UpdateVp {
    pub addr: Address,
    pub vp_code: Vec<u8>,
}

impl UpdateVp {
    /// Sign data for transaction with a given keypair.
    pub fn sign(
        self,
        tx_code: impl AsRef<[u8]>,
        keypair: &Keypair,
    ) -> SignedTxData {
        let bytes = self.try_to_vec().expect(
            "Encoding transfer data to update a validity predicate shouldn't \
             fail",
        );
        SignedTxData::new(keypair, bytes, tx_code)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Tests that any key that doesn't contain reserved prefixes is valid.
        /// This test excludes key segments starting with `#` or `?`
        /// because they are reserved for `Address` or a validity predicate.
        #[test]
        fn test_key_parse(s in "[^#?/][^/]*/[^#?/][^/]*/[^#?/][^/]*") {
            let key = Key::parse(s.clone()).expect("cannnot parse the string");
            assert_eq!(key.to_string(), s);
        }

        /// Tests that any key that doesn't contain reserved prefixes and
        /// separators is valid. This test excludes key segments including `/`
        /// or starting with `#` or `?` because they are reserved for separator,
        /// `Address` or validity predicate.
        #[test]
        fn test_key_push(s in "[^#?/][^/]*") {
            let addr = address::testing::established_address_1();
            let key = Key::from(addr.to_db_key()).push(&s).expect("cannnot push the segment");
            assert_eq!(key.segments[1].to_string(), s);
        }
    }

    #[test]
    fn test_key_parse_valid() {
        let addr = address::testing::established_address_1();
        let target = format!("{}/test", KeySeg::to_string(&addr));
        let key = Key::parse(target.clone()).expect("cannot parse the string");
        assert_eq!(key.to_string(), target);

        let target = "?test/test@".to_owned();
        let key = Key::parse(target.clone()).expect("cannot parse the string");
        assert_eq!(key.to_string(), target);
    }

    #[test]
    fn test_key_parse_invalid() {
        let target = "?/test".to_owned();
        match Key::parse(target).expect_err("unexpectedly succeeded") {
            Error::InvalidKeySeg(s) => assert_eq!(s, "?"),
            _ => panic!("unexpected error happens"),
        }
    }

    #[test]
    fn test_key_push_valid() {
        let addr = address::testing::established_address_1();
        let other = address::testing::established_address_2();
        let target = KeySeg::to_string(&other);
        let key = Key::from(addr.to_db_key())
            .push(&target)
            .expect("cannnot push the segment");
        assert_eq!(key.segments[1].to_string(), target);

        let target = "?test".to_owned();
        let key = Key::from(addr.to_db_key())
            .push(&target)
            .expect("cannnot push the segment");
        assert_eq!(key.segments[1].to_string(), target);
    }

    #[test]
    fn test_key_push_invalid() {
        let addr = address::testing::established_address_1();
        let target = "/".to_owned();
        match Key::from(addr.to_db_key())
            .push(&target)
            .expect_err("unexpectedly succeeded")
        {
            Error::InvalidKeySeg(s) => assert_eq!(s, "/"),
            _ => panic!("unexpected error happens"),
        }

        let target = "?".to_owned();
        match Key::from(addr.to_db_key())
            .push(&target)
            .expect_err("unexpectedly succeeded")
        {
            Error::InvalidKeySeg(s) => assert_eq!(s, "?"),
            _ => panic!("unexpected error happens"),
        }
    }
}
