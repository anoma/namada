//! The key and values that may be persisted in a DB.

use borsh::{BorshDeserialize, BorshSerialize};
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::traits::Hasher;
use sparse_merkle_tree::{SparseMerkleTree, H256};
use thiserror::Error;

use crate::bytes::ByteBuf;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Deserialization error: {0}")]
    DeserializationError(std::io::Error),
}

/// Result for functions that may fail
type Result<T> = std::result::Result<T, Error>;

/// Encode a value with borsh
pub fn encode<T>(value: &T) -> Vec<u8>
where
    T: BorshSerialize,
{
    let size = std::mem::size_of::<T>();
    let mut result = Vec::with_capacity(size);
    value.serialize(&mut result).expect("serialization failed");
    result
}

/// Decode a value with borsh
pub fn decode<T>(bytes: impl AsRef<[u8]>) -> Result<T>
where
    T: BorshDeserialize,
{
    T::try_from_slice(bytes.as_ref()).map_err(Error::DeserializationError)
}

/// Merkle tree storage
pub struct MerkleTree<H: Hasher + Default>(
    pub SparseMerkleTree<H, H256, DefaultStore<H256>>,
);

impl<H: Hasher + Default> Default for MerkleTree<H> {
    fn default() -> Self {
        MerkleTree(SparseMerkleTree::default())
    }
}

impl<H: Hasher + Default> core::fmt::Debug for MerkleTree<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let root_hash = format!("{}", ByteBuf(self.0.root().as_slice()));
        f.debug_struct("MerkleTree")
            .field("root_hash", &root_hash)
            .finish()
    }
}

/// A key-value pair as raw bytes
pub type KVBytes = (Box<[u8]>, Box<[u8]>);

/// Storage prefix iterator generic wrapper type.
pub struct PrefixIterator<I> {
    /// The concrete iterator implementation
    pub iter: I,
    /// The prefix that is being iterated
    pub db_prefix: String,
}

impl<I> PrefixIterator<I> {
    /// Initialize a new prefix iterator
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
