//! Traits needed to provide a uniform interface over
//! all the different Merkle trees used for storage
use std::convert::TryInto;
use std::fmt;

use arse_merkle_tree::traits::{Hasher, Value};
use arse_merkle_tree::{Key as TreeKey, H256};
use ics23::commitment_proof::Proof as Ics23Proof;
use ics23::{CommitmentProof, ExistenceProof};
use namada_core::types::storage::IBC_KEY_LIMIT;
use sha2::{Digest, Sha256};

use super::ics23_specs;
use super::merkle_tree::{Amt, Error, MembershipProof, Smt};
use crate::types::hash::Hash;
use crate::types::storage::{Key, MerkleValue, StringKey, TreeBytes};

/// Trait for reading from a merkle tree that is a sub-tree
/// of the global merkle tree.
pub trait SubTreeRead {
    /// Check if a key is present in the sub-tree
    fn subtree_has_key(&self, key: &Key) -> Result<bool, Error>;
    /// Get a membership proof for various key-value pairs
    fn subtree_membership_proof(
        &self,
        keys: &[Key],
        values: Vec<MerkleValue>,
    ) -> Result<MembershipProof, Error>;
}

/// Trait for updating a merkle tree that is a sub-tree
/// of the global merkle tree
pub trait SubTreeWrite {
    /// Add a key-value pair to the sub-tree
    fn subtree_update(
        &mut self,
        key: &Key,
        value: MerkleValue,
    ) -> Result<Hash, Error>;
    /// Delete a key from the sub-tree
    fn subtree_delete(&mut self, key: &Key) -> Result<Hash, Error>;
}

impl<'a, H: StorageHasher + Default> SubTreeRead for &'a Smt<H> {
    fn subtree_has_key(&self, key: &Key) -> Result<bool, Error> {
        match self.get(&H::hash(key.to_string()).into()) {
            Ok(hash) => Ok(!hash.is_zero()),
            Err(e) => Err(Error::MerkleTree(e.to_string())),
        }
    }

    fn subtree_membership_proof(
        &self,
        keys: &[Key],
        mut values: Vec<MerkleValue>,
    ) -> Result<MembershipProof, Error> {
        if keys.len() != 1 || values.len() != 1 {
            return Err(Error::Ics23MultiLeaf);
        }
        let key: &Key = &keys[0];
        let MerkleValue::Bytes(value) = values.remove(0);
        let cp = self.membership_proof(&H::hash(key.to_string()).into())?;
        // Replace the values and the leaf op for the verification
        match cp.proof.expect("The proof should exist") {
            Ics23Proof::Exist(ep) => Ok(CommitmentProof {
                proof: Some(Ics23Proof::Exist(ExistenceProof {
                    key: key.to_string().as_bytes().to_vec(),
                    value,
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
        value: MerkleValue,
    ) -> Result<Hash, Error> {
        let value = match value {
            MerkleValue::Bytes(bytes) => H::hash(bytes.as_slice()),
        };
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
    fn subtree_has_key(&self, key: &Key) -> Result<bool, Error> {
        let key = StringKey::try_from_bytes(key.to_string().as_bytes())?;
        match self.get(&key) {
            Ok(hash) => Ok(!hash.is_zero()),
            Err(e) => Err(Error::MerkleTree(e.to_string())),
        }
    }

    fn subtree_membership_proof(
        &self,
        keys: &[Key],
        _: Vec<MerkleValue>,
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
        value: MerkleValue,
    ) -> Result<Hash, Error> {
        let key = StringKey::try_from_bytes(key.to_string().as_bytes())?;
        let value = match value {
            MerkleValue::Bytes(bytes) => TreeBytes::from(bytes),
        };
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

/// The storage hasher used for the merkle tree.
pub trait StorageHasher: Hasher + Default {
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
