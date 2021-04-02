//! The key and values that may be persisted in a DB.

use std::convert::{TryFrom, TryInto};
use std::fmt::Display;

use anoma::bytes::ByteBuf;
use blake2b_rs::{Blake2b, Blake2bBuilder};
use borsh::{BorshDeserialize, BorshSerialize};
use sparse_merkle_tree::blake2b::Blake2bHasher;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::{SparseMerkleTree, H256};
use tendermint_proto::types::Block;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("TEMPORARY error: {error}")]
    Temporary { error: String },
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

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Address {
    Validator(ValidatorAddress),
    Basic(BasicAddress),
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let addr = match self {
            Address::Validator(ValidatorAddress(addr)) => addr,
            Address::Basic(BasicAddress(addr)) => addr,
        };
        f.write_str(addr)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BasicAddress(pub String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ValidatorAddress(pub String);

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

    /// Returns addresses from the segments
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
    fn parse(string: String) -> Result<Self> {
        match string.chars().nth(0) {
            Some(c) if c == '@' => {
                // TODO: single address type
                match string.chars().nth(1) {
                    Some(c) if c == 'b' => Ok(BasicAddress::parse(string)
                        .map(Address::Basic)
                        .map(DbKeySeg::AddressSeg)?),
                    _ => Ok(ValidatorAddress::parse(string)
                        .map(Address::Validator)
                        .map(DbKeySeg::AddressSeg)?),
                }
            }
            _ => Ok(DbKeySeg::StringSeg(string)),
        }
    }

    fn to_string(&self) -> String {
        match self {
            DbKeySeg::AddressSeg(addr) => ToString::to_string(&addr),
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

impl Hash256 for Address {
    fn hash256(&self) -> H256 {
        match self {
            Address::Basic(addr) => addr.hash256(),
            Address::Validator(addr) => addr.hash256(),
        }
    }
}
impl KeySeg for Address {
    fn to_string(&self) -> String {
        match self {
            Address::Validator(addr) => addr.to_string(),
            Address::Basic(addr) => addr.to_string(),
        }
    }

    fn parse(seg: String) -> Result<Self> {
        BasicAddress::parse(seg.clone())
            .map(Address::Basic)
            .or(ValidatorAddress::parse(seg.clone()).map(Address::Validator))
            .map_err(|_e| Error::Temporary {
                error: format!(
                    "TEMPORARY: Address must start with \"b\" or \"v\", got {}",
                    seg
                ),
            })
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::AddressSeg(self.clone())
    }
}

impl Hash256 for BasicAddress {
    fn hash256(&self) -> H256 {
        self.0.hash256()
    }
}
impl KeySeg for BasicAddress {
    fn to_string(&self) -> String {
        self.0.clone()
    }

    fn parse(seg: String) -> Result<Self> {
        match seg.chars().nth(0) {
            Some(c) if c == '@' => Ok(Self(seg.clone())),
            _ => Err(Error::Temporary {
                error: format!(
                    "TEMPORARY: BasicAddress must start with \"@b\", got {}",
                    seg
                ),
            }),
        }
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::AddressSeg(Address::Basic(self.clone()))
    }
}

impl Hash256 for ValidatorAddress {
    fn hash256(&self) -> H256 {
        self.0.hash256()
    }
}
impl KeySeg for ValidatorAddress {
    fn parse(seg: String) -> Result<Self> {
        match seg.chars().nth(0) {
            Some(c) if c == '@' => Ok(Self(seg.clone())),
            _ => Err(Error::Temporary {
                error: format!(
                    "TEMPORARY: ValidatorAddress must start with \"@v\", got {}",
                    seg
                ),
            }),
        }
    }

    fn to_string(&self) -> String {
        self.0.clone()
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::AddressSeg(Address::Validator(self.clone()))
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
