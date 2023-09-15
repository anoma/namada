//! Traits needed to provide a uniform interface over
//! all the different Merkle trees used for storage
use std::convert::TryInto;
use std::fmt;

use arse_merkle_tree::traits::{Hasher, Value};
use arse_merkle_tree::{Key as TreeKey, H256};
use borsh::BorshDeserialize;
use borsh_ext::BorshSerializeExt;
use ics23::commitment_proof::Proof as Ics23Proof;
use ics23::{CommitmentProof, ExistenceProof};
use sha2::{Digest, Sha256};
use tiny_keccak::Hasher as KHasher;

use super::ics23_specs;
use super::merkle_tree::{Amt, Error, MerkleRoot, Smt};
use crate::ledger::eth_bridge::storage::bridge_pool::BridgePoolTree;
use crate::ledger::storage::merkle_tree::StorageBytes;
use crate::types::eth_bridge_pool::PendingTransfer;
use crate::types::hash::Hash;
use crate::types::storage::{
    BlockHeight, Key, MembershipProof, StringKey, TreeBytes, IBC_KEY_LIMIT,
};

/// Trait for reading from a merkle tree that is a sub-tree
/// of the global merkle tree.
pub trait SubTreeRead {
    /// Get the root of a subtree in raw bytes.
    fn root(&self) -> MerkleRoot;
    /// Check if a key is present in the sub-tree
    fn subtree_has_key(&self, key: &Key) -> Result<bool, Error>;
    /// Get the height at which the key is inserted
    fn subtree_get(&self, key: &Key) -> Result<Vec<u8>, Error>;
    /// Get a membership proof for various key-value pairs
    fn subtree_membership_proof(
        &self,
        keys: &[Key],
        values: Vec<StorageBytes>,
    ) -> Result<MembershipProof, Error>;
}

/// Trait for updating a merkle tree that is a sub-tree
/// of the global merkle tree
pub trait SubTreeWrite {
    /// Add a key-value pair to the sub-tree
    fn subtree_update(
        &mut self,
        key: &Key,
        value: StorageBytes,
    ) -> Result<Hash, Error>;
    /// Delete a key from the sub-tree
    fn subtree_delete(&mut self, key: &Key) -> Result<Hash, Error>;
}

impl<'a, H: StorageHasher + Default> SubTreeRead for &'a Smt<H> {
    fn root(&self) -> MerkleRoot {
        Smt::<H>::root(self).into()
    }

    fn subtree_has_key(&self, key: &Key) -> Result<bool, Error> {
        match self.get(&H::hash(key.to_string()).into()) {
            Ok(hash) => Ok(!hash.is_zero()),
            Err(e) => Err(Error::MerkleTree(e.to_string())),
        }
    }

    fn subtree_get(&self, key: &Key) -> Result<Vec<u8>, Error> {
        match self.get(&H::hash(key.to_string()).into()) {
            Ok(hash) => Ok(hash.0.to_vec()),
            Err(err) => Err(Error::MerkleTree(err.to_string())),
        }
    }

    fn subtree_membership_proof(
        &self,
        keys: &[Key],
        mut values: Vec<StorageBytes>,
    ) -> Result<MembershipProof, Error> {
        if keys.len() != 1 || values.len() != 1 {
            return Err(Error::Ics23MultiLeaf);
        }
        let key: &Key = &keys[0];
        let value = values.remove(0);
        let cp = self.membership_proof(&H::hash(key.to_string()).into())?;
        // Replace the values and the leaf op for the verification
        match cp.proof.expect("The proof should exist") {
            Ics23Proof::Exist(ep) => Ok(CommitmentProof {
                proof: Some(Ics23Proof::Exist(ExistenceProof {
                    key: key.to_string().as_bytes().to_vec(),
                    value: value.to_vec(),
                    leaf: Some(ics23_specs::leaf_spec::<H>()),
                    ..ep
                })),
            }
            .into()),
            // the proof should have an ExistenceProof
            _ => unreachable!(),
        }
    }
}

impl<'a, H: StorageHasher + Default> SubTreeWrite for &'a mut Smt<H> {
    fn subtree_update(
        &mut self,
        key: &Key,
        value: StorageBytes,
    ) -> Result<Hash, Error> {
        let value = H::hash(value);
        self.update(H::hash(key.to_string()).into(), value.into())
            .map(Hash::from)
            .map_err(|err| Error::MerkleTree(err.to_string()))
    }

    fn subtree_delete(&mut self, key: &Key) -> Result<Hash, Error> {
        let value = Hash::zero();
        self.update(H::hash(key.to_string()).into(), value)
            .map(Hash::from)
            .map_err(|err| Error::MerkleTree(err.to_string()))
    }
}

impl<'a, H: StorageHasher + Default> SubTreeRead for &'a Amt<H> {
    fn root(&self) -> MerkleRoot {
        Amt::<H>::root(self).into()
    }

    fn subtree_has_key(&self, key: &Key) -> Result<bool, Error> {
        let key = StringKey::try_from_bytes(key.to_string().as_bytes())?;
        match self.get(&key) {
            Ok(hash) => Ok(!hash.is_zero()),
            Err(e) => Err(Error::MerkleTree(e.to_string())),
        }
    }

    fn subtree_get(&self, key: &Key) -> Result<Vec<u8>, Error> {
        let key = StringKey::try_from_bytes(key.to_string().as_bytes())?;
        match self.get(&key) {
            Ok(tree_bytes) => Ok(tree_bytes.into()),
            Err(err) => Err(Error::MerkleTree(err.to_string())),
        }
    }

    fn subtree_membership_proof(
        &self,
        keys: &[Key],
        _: Vec<StorageBytes>,
    ) -> Result<MembershipProof, Error> {
        if keys.len() != 1 {
            return Err(Error::Ics23MultiLeaf);
        }

        let key = StringKey::try_from_bytes(keys[0].to_string().as_bytes())?;
        let cp = self.membership_proof(&key)?;
        // Replace the values and the leaf op for the verification
        match cp.proof.expect("The proof should exist") {
            Ics23Proof::Exist(ep) => Ok(CommitmentProof {
                proof: Some(Ics23Proof::Exist(ExistenceProof {
                    leaf: Some(ics23_specs::ibc_leaf_spec::<H>()),
                    ..ep
                })),
            }
            .into()),
            // the proof should have an ExistenceProof
            _ => unreachable!(),
        }
    }
}

impl<'a, H: StorageHasher + Default> SubTreeWrite for &'a mut Amt<H> {
    fn subtree_update(
        &mut self,
        key: &Key,
        value: StorageBytes,
    ) -> Result<Hash, Error> {
        let key = StringKey::try_from_bytes(key.to_string().as_bytes())?;
        let value = TreeBytes::from(value.to_vec());
        self.update(key, value)
            .map(Into::into)
            .map_err(|err| Error::MerkleTree(err.to_string()))
    }

    fn subtree_delete(&mut self, key: &Key) -> Result<Hash, Error> {
        let key = StringKey::try_from_bytes(key.to_string().as_bytes())?;
        let value = TreeBytes::zero();
        self.update(key, value)
            .map(Hash::from)
            .map_err(|err| Error::MerkleTree(format!("{:?}", err)))
    }
}

impl<'a> SubTreeRead for &'a BridgePoolTree {
    fn root(&self) -> MerkleRoot {
        BridgePoolTree::root(self).into()
    }

    fn subtree_has_key(&self, key: &Key) -> Result<bool, Error> {
        self.contains_key(key)
            .map_err(|err| Error::MerkleTree(err.to_string()))
    }

    fn subtree_get(&self, key: &Key) -> Result<Vec<u8>, Error> {
        match self.get(key) {
            Ok(height) => Ok(height.serialize_to_vec()),
            Err(err) => Err(Error::MerkleTree(err.to_string())),
        }
    }

    fn subtree_membership_proof(
        &self,
        _: &[Key],
        values: Vec<StorageBytes>,
    ) -> Result<MembershipProof, Error> {
        let values = values
            .iter()
            .filter_map(|val| PendingTransfer::try_from_slice(val).ok())
            .collect();
        self.get_membership_proof(values)
            .map(Into::into)
            .map_err(|err| Error::MerkleTree(err.to_string()))
    }
}

impl<'a> SubTreeWrite for &'a mut BridgePoolTree {
    fn subtree_update(
        &mut self,
        key: &Key,
        value: StorageBytes,
    ) -> Result<Hash, Error> {
        let height = BlockHeight::try_from_slice(value)
            .map_err(|err| Error::MerkleTree(err.to_string()))?;
        self.insert_key(key, height)
            .map_err(|err| Error::MerkleTree(err.to_string()))
    }

    fn subtree_delete(&mut self, key: &Key) -> Result<Hash, Error> {
        self.delete_key(key)
            .map_err(|err| Error::MerkleTree(err.to_string()))?;
        Ok(self.root().into())
    }
}

impl TreeKey<IBC_KEY_LIMIT> for StringKey {
    type Error = Error;

    fn as_slice(&self) -> &[u8] {
        &self.original.as_slice()[..self.length]
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut tree_key = [0u8; IBC_KEY_LIMIT];
        let mut original = [0u8; IBC_KEY_LIMIT];
        let mut length = 0;
        for (i, byte) in bytes.iter().enumerate() {
            if i >= IBC_KEY_LIMIT {
                return Err(Error::InvalidMerkleKey(
                    "Input IBC key is too large".into(),
                ));
            }
            original[i] = *byte;
            tree_key[i] = byte.wrapping_add(1);
            length += 1;
        }
        Ok(Self {
            original,
            tree_key: tree_key.into(),
            length,
        })
    }
}

impl Value for Hash {
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn zero() -> Self {
        Hash([0u8; 32])
    }
}

impl From<Hash> for H256 {
    fn from(hash: Hash) -> Self {
        hash.0.into()
    }
}

impl From<H256> for Hash {
    fn from(hash: H256) -> Self {
        Self(hash.into())
    }
}

impl From<&H256> for Hash {
    fn from(hash: &H256) -> Self {
        let hash = hash.to_owned();
        Self(hash.into())
    }
}

impl Value for TreeBytes {
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn zero() -> Self {
        TreeBytes::zero()
    }
}

/// The storage hasher used for the merkle tree.
pub trait StorageHasher: Hasher + fmt::Debug + Default {
    /// Hash the value to store
    fn hash(value: impl AsRef<[u8]>) -> H256;
}

/// The storage hasher used for the merkle tree.
#[derive(Default)]
pub struct Sha256Hasher(Sha256);

impl Hasher for Sha256Hasher {
    fn write_bytes(&mut self, h: &[u8]) {
        self.0.update(h)
    }

    fn finish(self) -> H256 {
        let hash = self.0.finalize();
        let bytes: [u8; 32] = hash
            .as_slice()
            .try_into()
            .expect("Sha256 output conversion to fixed array shouldn't fail");
        bytes.into()
    }

    fn hash_op() -> ics23::HashOp {
        ics23::HashOp::Sha256
    }
}

impl StorageHasher for Sha256Hasher {
    fn hash(value: impl AsRef<[u8]>) -> H256 {
        let mut hasher = Sha256::new();
        hasher.update(value.as_ref());
        let hash = hasher.finalize();
        let bytes: [u8; 32] = hash
            .as_slice()
            .try_into()
            .expect("Sha256 output conversion to fixed array shouldn't fail");
        bytes.into()
    }
}

impl fmt::Debug for Sha256Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Hasher")
    }
}

/// A Keccak hasher algorithm.
pub struct KeccakHasher(tiny_keccak::Keccak);

impl fmt::Debug for KeccakHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeccakHasher")
    }
}

impl Default for KeccakHasher {
    fn default() -> Self {
        Self(tiny_keccak::Keccak::v256())
    }
}

impl StorageHasher for KeccakHasher {
    fn hash(value: impl AsRef<[u8]>) -> H256 {
        use tiny_keccak::Keccak;
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(value.as_ref());
        hasher.finalize(&mut output);
        output.into()
    }
}

impl Hasher for KeccakHasher {
    fn write_bytes(&mut self, h: &[u8]) {
        self.0.update(h);
    }

    fn finish(self) -> H256 {
        let mut output = [0; 32];
        self.0.finalize(&mut output);
        output.into()
    }
}

/// A [`StorageHasher`] which can never be called.
#[derive(Debug)]
pub enum DummyHasher {}

const DUMMY_HASHER_PANIC_MSG: &str = "A storage hasher was called, which \
                                      should never have been reachable from \
                                      any code path";

impl Default for DummyHasher {
    fn default() -> Self {
        unreachable!("{DUMMY_HASHER_PANIC_MSG}")
    }
}

impl StorageHasher for DummyHasher {
    fn hash(_: impl AsRef<[u8]>) -> H256 {
        unreachable!("{DUMMY_HASHER_PANIC_MSG}")
    }
}

impl Hasher for DummyHasher {
    fn write_bytes(&mut self, _: &[u8]) {
        unreachable!("{DUMMY_HASHER_PANIC_MSG}")
    }

    fn finish(self) -> H256 {
        unreachable!("{DUMMY_HASHER_PANIC_MSG}")
    }
}
