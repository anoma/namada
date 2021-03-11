//! The key and values that may be persisted in a DB.

use anoma::bytes::ByteBuf;
use blake2b_rs::{Blake2b, Blake2bBuilder};
use borsh::{BorshDeserialize, BorshSerialize};
use sparse_merkle_tree::{
    blake2b::Blake2bHasher, default_store::DefaultStore, SparseMerkleTree, H256,
};
use std::convert::{TryFrom, TryInto};

// TODO adjust once chain ID scheme is chosen, add `Default` impl that allocates
// this
pub const CHAIN_ID_LENGTH: usize = 20;
const BLOCK_HASH_LENGTH: usize = 32;
// TODO customize for different types (derive from `size_of`?)
const DEFAULT_SERIALIZER_CAPACITY: usize = 1024;

#[derive(
    Clone,
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

impl Address {
    pub fn new_address(addr: String) -> Self {
        match addr.chars().nth(0) {
            Some(c) if c == 'v' => ValidatorAddress::new_address(addr),
            _ => BasicAddress::new_address(addr),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BasicAddress(pub String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ValidatorAddress(pub String);

#[derive(
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Debug,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
)]
pub struct Balance(pub u64);

// TODO make a derive macro for Hash256 https://doc.rust-lang.org/book/ch19-06-macros.html#how-to-write-a-custom-derive-macro
pub trait Hash256 {
    fn hash256(&self) -> H256;
}

// TODO use std::convert::{TryFrom, Into}?
/// Represents a segment in a path that may be used as a database key
pub trait KeySeg {
    /// Convert `Self` to a key segment. This mapping should preserve the
    /// ordering of `Self`
    fn to_key_seg(&self) -> String;

    /// Reverse of `to_key_seg`. Convert key segment to `Self`.
    fn from_key_seg(seg: &String) -> Result<Self, String>
    where
        Self: Sized;
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
impl Value for Balance {}
impl Value for BlockHeight {}
impl Value for BlockHash {}
impl Value for H256 {}
impl<T: Value> Value for DefaultStore<T> {}

impl KeySeg for BlockHeight {
    fn to_key_seg(&self) -> String {
        format!("{}", self.0)
    }

    fn from_key_seg(_seg: &String) -> Result<Self, String> {
        todo!()
    }
}
impl TryFrom<i64> for BlockHeight {
    type Error = String;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        value
            .try_into()
            .map(BlockHeight)
            .map_err(|e| format!("Unexpected height value {}, {}", value, e))
    }
}

impl Default for BlockHash {
    fn default() -> Self {
        Self([0; 32])
    }
}
impl TryFrom<&[u8]> for BlockHash {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, String> {
        if value.len() != BLOCK_HASH_LENGTH {
            return Err(format!(
                "Unexpected block hash length {}, expected {}",
                value.len(),
                BLOCK_HASH_LENGTH
            ));
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(value);
        Ok(BlockHash(hash))
    }
}
impl TryFrom<Vec<u8>> for BlockHash {
    type Error = String;

    fn try_from(value: Vec<u8>) -> Result<Self, String> {
        if value.len() != BLOCK_HASH_LENGTH {
            return Err(format!(
                "Unexpected block hash length {}, expected {}",
                value.len(),
                BLOCK_HASH_LENGTH
            ));
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
    fn to_key_seg(&self) -> String {
        match self {
            Address::Validator(addr) => addr.to_key_seg(),
            Address::Basic(addr) => addr.to_key_seg(),
        }
    }

    fn from_key_seg(seg: &String) -> Result<Self, String> {
        BasicAddress::from_key_seg(seg)
            .map(Address::Basic)
            .or(ValidatorAddress::from_key_seg(seg).map(Address::Validator))
            .map_err(|_e| {
                format!("Address must start with \"b\" or \"v\", got {}", seg)
                    .to_owned()
            })
    }
}

impl BasicAddress {
    pub fn new_address(addr: String) -> Address {
        Address::Basic(Self(addr))
    }
}

impl Hash256 for BasicAddress {
    fn hash256(&self) -> H256 {
        self.0.hash256()
    }
}
impl KeySeg for BasicAddress {
    fn to_key_seg(&self) -> String {
        self.0.clone()
    }

    fn from_key_seg(seg: &String) -> Result<Self, String> {
        match seg.chars().nth(0) {
            Some(c) if c == 'b' => Ok(Self(seg.clone())),
            _ => Err("BasicAddress must start with \"b\"".to_owned()),
        }
    }
}

impl ValidatorAddress {
    pub fn new_address(addr: String) -> Address {
        Address::Validator(Self(addr))
    }
}
impl Hash256 for ValidatorAddress {
    fn hash256(&self) -> H256 {
        self.0.hash256()
    }
}
impl KeySeg for ValidatorAddress {
    fn to_key_seg(&self) -> String {
        self.0.clone()
    }

    fn from_key_seg(seg: &String) -> Result<Self, String> {
        match seg.chars().nth(0) {
            Some(c) if c == 'v' => Ok(Self(seg.clone())),
            _ => Err("ValidatorAddress must start with \"v\"".to_owned()),
        }
    }
}

impl Balance {
    pub fn new(balance: u64) -> Self {
        Self(balance)
    }
}
impl Hash256 for Balance {
    fn hash256(&self) -> H256 {
        if self.0 == 0 {
            return H256::zero();
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&self.encode());
        hasher.finalize(&mut buf);
        buf.into()
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

fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"anoma storage").build()
}
