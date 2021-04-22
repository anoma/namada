//! The key and values that may be persisted in a DB.

use anoma_shared::bytes::ByteBuf;
use anoma_shared::types::{Address, BlockHash, BlockHeight, Key};
use blake2b_rs::{Blake2b, Blake2bBuilder};
use borsh::{BorshDeserialize, BorshSerialize};
use sparse_merkle_tree::blake2b::Blake2bHasher;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::{SparseMerkleTree, H256};

// TODO customize for different types (derive from `size_of`?)
const DEFAULT_SERIALIZER_CAPACITY: usize = 1024;

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

// TODO make a derive macro for Hash256 https://doc.rust-lang.org/book/ch19-06-macros.html#how-to-write-a-custom-derive-macro
pub trait Hash256 {
    fn hash256(&self) -> H256;
}

pub struct MerkleTree(
    pub SparseMerkleTree<Blake2bHasher, H256, DefaultStore<H256>>,
);

impl Default for MerkleTree {
    fn default() -> Self {
        MerkleTree(SparseMerkleTree::default())
    }
}

impl core::fmt::Debug for MerkleTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let root_hash = format!("{}", ByteBuf(self.0.root().as_slice()));
        f.debug_struct("MerkleTree")
            .field("root_hash", &root_hash)
            .finish()
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
    type Item = (String, Vec<u8>, u64);

    fn next(&mut self) -> Option<(String, Vec<u8>, u64)> {
        match self.iter.next() {
            Some((key, val)) => {
                let len = val.len();
                let key = String::from_utf8(key.to_vec())
                    .expect("Cannot convert from bytes to key string");
                match key.strip_prefix(&self.db_prefix) {
                    Some(k) => Some((k.to_owned(), val.to_vec(), len as _)),
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

impl Hash256 for Address {
    fn hash256(&self) -> H256 {
        self.hash.hash256()
    }
}
