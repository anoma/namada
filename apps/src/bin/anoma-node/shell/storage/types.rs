//! The key and values that may be persisted in a DB.

use anoma_shared::bytes::ByteBuf;
use blake2b_rs::{Blake2b, Blake2bBuilder};
use borsh::{BorshDeserialize, BorshSerialize};
use sparse_merkle_tree::blake2b::Blake2bHasher;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::{SparseMerkleTree, H256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Deserialization error: {0}")]
    DeserializationError(std::io::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub fn encode<T>(value: &T) -> Vec<u8>
where
    T: BorshSerialize,
{
    let size = std::mem::size_of::<T>();
    let mut result = Vec::with_capacity(size);
    value.serialize(&mut result).expect("serialization failed");
    result
}

pub fn decode<T>(bytes: impl AsRef<[u8]>) -> Result<T>
where
    T: BorshDeserialize,
{
    T::try_from_slice(bytes.as_ref()).map_err(Error::DeserializationError)
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

pub trait Hash256 {
    fn hash256(&self) -> H256;
}

impl<T> Hash256 for T
where
    T: BorshSerialize,
{
    fn hash256(&self) -> H256 {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&encode(&self));
        hasher.finalize(&mut buf);
        buf.into()
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
