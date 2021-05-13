//! The key and values that may be persisted in a DB.

use anoma_shared::bytes::ByteBuf;
use anoma_shared::types::{Address, Key};
use blake2b_rs::{Blake2b, Blake2bBuilder};
use borsh::{BorshDeserialize, BorshSerialize};
use sparse_merkle_tree::blake2b::Blake2bHasher;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::{SparseMerkleTree, H256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Serialization error {0}")]
    SerializationError(std::io::Error),
    #[error("Deserialization error: {0}")]
    DeserializationError(std::io::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub fn encode<T>(value: &T) -> Result<Vec<u8>>
where
    T: BorshSerialize,
{
    let size = std::mem::size_of::<T>();
    let mut result = Vec::with_capacity(size);
    value
        .serialize(&mut result)
        .map_err(Error::SerializationError)?;
    Ok(result)
}

pub fn decode<T>(bytes: impl AsRef<[u8]>) -> Result<T>
where
    T: BorshDeserialize,
{
    T::try_from_slice(bytes.as_ref()).map_err(Error::DeserializationError)
}

// TODO make a derive macro for Hash256 https://doc.rust-lang.org/book/ch19-06-macros.html#how-to-write-a-custom-derive-macro
pub trait Hash256 {
    fn hash256(&self) -> Result<H256>;
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
    fn hash256(&self) -> Result<H256> {
        if self.is_empty() {
            return Ok(H256::zero());
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&encode(&self.to_string())?);
        hasher.finalize(&mut buf);
        Ok(buf.into())
    }
}

impl Hash256 for String {
    fn hash256(&self) -> Result<H256> {
        if self.is_empty() {
            return Ok(H256::zero());
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&encode(self)?);
        hasher.finalize(&mut buf);
        Ok(buf.into())
    }
}

impl Hash256 for [u8; 32] {
    fn hash256(&self) -> Result<H256> {
        if self.is_empty() {
            return Ok(H256::zero());
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(self);
        hasher.finalize(&mut buf);
        Ok(buf.into())
    }
}

impl Hash256 for u64 {
    fn hash256(&self) -> Result<H256> {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&encode(self)?);
        hasher.finalize(&mut buf);
        Ok(buf.into())
    }
}

impl Hash256 for Vec<u8> {
    fn hash256(&self) -> Result<H256> {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&self.as_slice());
        hasher.finalize(&mut buf);
        Ok(buf.into())
    }
}

impl Hash256 for Key {
    fn hash256(&self) -> Result<H256> {
        self.to_string().hash256()
    }
}

fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"anoma storage").build()
}

pub type KVBytes = (Box<[u8]>, Box<[u8]>);

pub struct PrefixIterator<I> {
    pub iter: I,
    pub db_prefix: String,
}

impl<I> PrefixIterator<I> {
    pub fn new(iter: I, db_prefix: String) -> Self
    where
        I: Iterator<Item = KVBytes>,
    {
        PrefixIterator { iter, db_prefix }
    }
}

impl<I> std::fmt::Debug for PrefixIterator<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrefixIterator")
    }
}

impl Hash256 for Address {
    fn hash256(&self) -> Result<H256> {
        self.try_to_vec()
            .expect("Encoding address shouldn't fail")
            .hash256()
    }
}
