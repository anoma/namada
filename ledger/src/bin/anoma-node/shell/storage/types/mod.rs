//! The key and values that may be persisted in a DB.

mod address;

pub use address::{Address, RawAddress};

use std::fmt::Display;
use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
};

use anoma::bytes::ByteBuf;
use blake2b_rs::{Blake2b, Blake2bBuilder};
use borsh::{BorshDeserialize, BorshSerialize};
use sparse_merkle_tree::blake2b::Blake2bHasher;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::{SparseMerkleTree, H256};
use thiserror::Error;

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
const BLOCK_HASH_LENGTH: usize = 32;
// TODO customize for different types (derive from `size_of`?)
const DEFAULT_SERIALIZER_CAPACITY: usize = 1024;

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
pub struct BlockHash([u8; 32]);

pub struct MerkleTree(
    pub SparseMerkleTree<Blake2bHasher, H256, DefaultStore<H256>>,
);

// TODO make a derive macro for Hash256 https://doc.rust-lang.org/book/ch19-06-macros.html#how-to-write-a-custom-derive-macro
pub trait Hash256 {
    fn hash256(&self) -> H256;
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Key {
    segments: Vec<DbKeySeg>,
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

    /// Returns string from the segments
    pub fn to_string(&self) -> String {
        let v: Vec<String> = self
            .segments
            .iter()
            .map(|s| DbKeySeg::to_string(s))
            .collect();
        v.join("/")
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
}

impl Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string())
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

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DbKeySeg {
    AddressSeg(Address),
    StringSeg(String),
}

impl KeySeg for DbKeySeg {
    fn parse(mut string: String) -> Result<Self> {
        match string.chars().nth(0) {
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

/// Represents a value that can be written and read from the database
pub trait Value: BorshSerialize + BorshDeserialize {
    fn encode(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY);
        // TODO error handling
        self.serialize(&mut result).unwrap();
        result
    }

    fn decode(bytes: Vec<u8>) -> Self {
        // TODO error handling
        Self::try_from_slice(&bytes).unwrap()
    }
}

// TODO is there a better way to do this?
impl Value for String {}
impl Value for u64 {}
impl Value for i64 {}
impl Value for BlockHeight {}
impl Value for BlockHash {}
impl Value for H256 {}
impl<T: Value> Value for DefaultStore<T> {}

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
        match seg.chars().nth(0) {
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

impl Hash256 for &str {
    fn hash256(&self) -> H256 {
        if self.is_empty() {
            return H256::zero();
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&self.to_string().encode());
        hasher.finalize(&mut buf);
        buf.into()
    }
}

impl Hash256 for String {
    fn hash256(&self) -> H256 {
        if self.is_empty() {
            return H256::zero();
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&self.encode());
        hasher.finalize(&mut buf);
        buf.into()
    }
}

impl Hash256 for [u8; 32] {
    fn hash256(&self) -> H256 {
        if self.is_empty() {
            return H256::zero();
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(self);
        hasher.finalize(&mut buf);
        buf.into()
    }
}

impl Hash256 for u64 {
    fn hash256(&self) -> H256 {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&self.encode());
        hasher.finalize(&mut buf);
        buf.into()
    }
}

impl Hash256 for Vec<u8> {
    fn hash256(&self) -> H256 {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&self.as_slice());
        hasher.finalize(&mut buf);
        buf.into()
    }
}

impl Hash256 for Key {
    fn hash256(&self) -> H256 {
        self.to_string().hash256()
    }
}

fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"anoma storage").build()
}

pub struct PrefixIterator<'a> {
    iter: rocksdb::DBIterator<'a>,
    db_prefix: String,
}

impl<'a> PrefixIterator<'a> {
    pub fn new(iter: rocksdb::DBIterator<'a>, db_prefix: String) -> Self {
        PrefixIterator { iter, db_prefix }
    }
}

impl<'a> Iterator for PrefixIterator<'a> {
    type Item = (String, Vec<u8>);

    fn next(&mut self) -> Option<(String, Vec<u8>)> {
        match self.iter.next() {
            Some((key, val)) => {
                let key = String::from_utf8(key.to_vec())
                    .expect("Cannot convert from bytes to key string");
                match key.strip_prefix(&self.db_prefix) {
                    Some(k) => Some((k.to_owned(), val.to_vec())),
                    None => self.next(),
                }
            }
            None => None,
        }
    }
}

impl<'a> std::fmt::Debug for PrefixIterator<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrefixIterator")
    }
}
