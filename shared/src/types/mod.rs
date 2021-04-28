//! The key and values that may be persisted in a DB.

pub mod address;

use std::convert::{TryFrom, TryInto};
use std::fmt::Display;
use std::str::FromStr;

pub use address::{Address, RawAddress};
use borsh::{BorshDeserialize, BorshSerialize};
use thiserror::Error;

use crate::bytes::ByteBuf;

#[derive(Error, Debug)]
pub enum Error {
    #[error("TEMPORARY error: {error}")]
    Temporary { error: String },
    #[error("Error parsing address: {0}")]
    ParseAddress(address::Error),
    #[error("Error parsing address from a storage key")]
    ParseAddressFromKey,
}

pub type Result<T> = std::result::Result<T, Error>;

// TODO adjust once chain ID scheme is chosen, add `Default` impl that allocates
// this
pub const CHAIN_ID_LENGTH: usize = 20;
pub const BLOCK_HASH_LENGTH: usize = 32;

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
)]
pub struct BlockHeight(pub u64);

#[derive(
    Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq, PartialOrd, Ord,
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
        for s in string.split('/') {
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

    pub fn validity_predicate(addr: &Address) -> Result<Self> {
        Self::from(addr.to_db_key()).push(&"?".to_owned())
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let segs: Vec<String> = self
            .segments
            .iter()
            .map(|s| DbKeySeg::to_string(s))
            .collect();
        let key = segs.join("/");
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
)]
pub enum DbKeySeg {
    AddressSeg(Address),
    StringSeg(String),
}

impl KeySeg for DbKeySeg {
    fn parse(mut string: String) -> Result<Self> {
        match string.chars().next() {
            // TODO reserve non-alphanumerical prefix characters for internal
            // usage raw addresses are prefixed with `'@'`
            Some(c) if c == '@' => {
                let _ = string.remove(0);
                FromStr::from_str(&string)
                    .map_err(Error::ParseAddress)
                    .map(|raw: RawAddress| DbKeySeg::AddressSeg(raw.hash()))
            }
            // address hashes are prefixed with `'#'`
            Some(c) if c == '#' => {
                let _ = string.remove(0);
                Address::decode(&string)
                    .map_err(Error::ParseAddress)
                    .map(DbKeySeg::AddressSeg)
            }
            _ => Ok(DbKeySeg::StringSeg(string)),
        }
    }

    fn to_string(&self) -> String {
        match self {
            DbKeySeg::AddressSeg(addr) => {
                format!("#{}", addr.encode())
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

impl KeySeg for RawAddress {
    fn to_string(&self) -> String {
        format!("@{}", self)
    }

    fn parse(mut seg: String) -> Result<Self> {
        match seg.chars().next() {
            Some(c) if c == '@' => {
                let _ = seg.remove(0);
                FromStr::from_str(&seg).map_err(Error::ParseAddress)
            }
            _ => Err(Error::ParseAddressFromKey),
        }
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::AddressSeg(self.hash())
    }
}

impl KeySeg for Address {
    fn to_string(&self) -> String {
        format!("#{}", self)
    }

    fn parse(mut seg: String) -> Result<Self> {
        match seg.chars().next() {
            Some(c) if c == '#' => {
                let _ = seg.remove(0);
                Ok(From::from(seg))
            }
            _ => Err(Error::ParseAddressFromKey),
        }
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::AddressSeg(self.clone())
    }
}
