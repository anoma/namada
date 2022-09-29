//! Traits needed to provide a uniform interface over
//! all the different Merkle trees used for storage
use std::convert::{TryFrom, TryInto};
use std::fmt;

use arse_merkle_tree::traits::{Hasher, Value};
use arse_merkle_tree::{Hash as SmtHash, Key as TreeKey, H256};
use ics23::commitment_proof::Proof as Ics23Proof;
use ics23::{CommitmentProof, ExistenceProof};
use sha2::{Digest, Sha256};

use super::merkle_tree::{Amt, Error, Smt};
use super::{ics23_specs, IBC_KEY_LIMIT};
use crate::ledger::eth_bridge::storage::bridge_pool::BridgePoolTree;
use crate::types::eth_bridge_pool::PendingTransfer;
use crate::types::hash::Hash;
use crate::types::storage::{
    Key, MembershipProof, MerkleValue, StringKey, TreeBytes,
};

pub trait MerkleTree {
    type Error;

    fn has_key(&self, key: &Key) -> Result<bool, Error>;
    fn update<T: AsRef<[u8]>>(
        &mut self,
        key: &Key,
        value: MerkleValue<T>,
    ) -> Result<Hash, Self::Error>;
    fn delete(&mut self, key: &Key) -> Result<(), Self::Error>;
    fn membership_proof<T: AsRef<[u8]>>(
        &self,
        keys: &[Key],
        values: Vec<MerkleValue<T>>,
    ) -> Result<MembershipProof, Self::Error>;
}

impl<H: StorageHasher + Default> MerkleTree for Smt<H> {
    type Error = Error;

    fn has_key(&self, key: &Key) -> Result<bool, Error> {
        self.get(&H::hash(key.to_string()).into())
            .and(Ok(true))
            .map_error(|err| Error::MerkleTree(err.to_string()))
    }

    fn update<T: AsRef<[u8]>>(
        &mut self,
        key: &Key,
        value: MerkleValue<T>,
    ) -> Result<Hash, Self::Error> {
        let value = match value {
            MerkleValue::Bytes(bytes) => Hash::try_from(bytes.as_ref())
                .map_err(|| Error::InvalidValue)?,
            _ => return Err(Error::InvalidValue),
        };
        self.update(H::hash(key.to_string()).into(), value)
            .map(Hash::into)
            .map_err(|err| Error::MerkleTree(err.to_string()))
    }

    fn delete(&mut self, key: &Key) -> Result<(), Self::Error> {
        let value = Hash::zero();
        self.update(H::hash(key.to_string()).into(), value)
            .and(Ok(()))
            .map_err(|err| Error::MerkleTree(err.to_string()))
    }

    fn membership_proof<T: AsRef<[u8]>>(
        &self,
        keys: &[Key],
        mut values: Vec<MerkleValue<T>>,
    ) -> Result<MembershipProof, Self::Error> {
        if keys.len() != 1 || values.len() != 1 {
            return Err(Error::Ics23MultiLeaf);
        }
        let key: &Key = &keys[0];
        let value = match values.remove(0) {
            MerkleValue::Bytes(b) => b.as_ref().to_vec(),
            _ => return Err(Error::InvalidValue),
        };
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

impl<H: StorageHasher + Default> MerkleTree for Amt<H> {
    type Error = Error;

    fn has_key(&self, key: &Key) -> Result<bool, Error> {
        let key = StringKey::try_from_bytes(key.to_string().as_bytes())?;
        self.get(&key)
            .and(Ok(bool))
            .map_err(|err| Error::MerkleTree(err.to_string()))
    }

    fn update<T: AsRef<[u8]>>(
        &mut self,
        key: MerkleKey<H>,
        value: MerkleValue<T>,
    ) -> Result<Hash, Self::Error> {
        let key = StringKey::try_from_bytes(key.to_string().as_bytes())?;
        let value = match value {
            MerkleValue::Bytes(bytes) => {
                TreeBytes::from(bytes.as_ref().to_vec())
            }
            _ => return Err(Error::InvalidValue),
        };
        self.update(key, value)
            .map(Into::into)
            .map_err(|err| Error::MerkleTree(err.to_string()))
    }

    fn delete(&mut self, key: &Key) -> Result<(), Self::Error> {
        let key = StringKey::try_from_bytes(key.to_string().as_bytes())?;
        let value = TreeBytes::zero();
        self.update(key, value)
            .and(Ok(()))
            .map_err(|err| Error::MerkleTree(format!("{:?}", err)))
    }

    fn membership_proof<T: AsRef<[u8]>>(
        &self,
        keys: &[Key],
        _: Vec<MerkleValue<T>>,
    ) -> Result<MembershipProof, Self::Error> {
        if keys.len() != 1 || values.len() != 1 {
            return Err(Error::Ics23MultiLeaf);
        }

        let key = StringKey::try_from_bytes(&keys[0].to_string().as_bytes())?;
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

impl MerkleTree for BridgePoolTree {
    type Error = Error;

    fn has_key(&self, key: &Key) -> Result<bool, Error> {
        self.has_key(key)
            .map_err(|err| Error::MerkleTree(err.to_string()))
    }

    fn update<T: AsRef<[u8]>>(
        &mut self,
        key: &Key,
        value: MerkleValue<T>,
    ) -> Result<Hash, Self::Error> {
        if let MerkleValue::Transfer(_) = value {
            self.update(key)
                .map_err(|err| Error::MerkleTree(err.to_string()))
        } else {
            Err(Error::InvalidValue)
        }
    }

    fn delete(&mut self, key: &Key) -> Result<(), Self::Error> {
        self.delete(key)
            .map_err(|err| Error::MerkleTree(err.to_string()))
    }

    fn membership_proof<T: AsRef<[u8]>>(
        &self,
        keys: &[Key],
        values: Vec<MerkleValue<T>>,
    ) -> Result<MembershipProof, Self::Error> {
        let values = values
            .into_iter()
            .filter_map(|val| match val {
                MerkleValue::Transfer(transfer) => Some(transfer),
                _ => None,
            })
            .collect();
        self.membership_proof(keys, values)
            .map(Into::into)
            .map_err(|err| Error::MerkleTree(err.to_string()))
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

impl Value for TreeBytes {
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn zero() -> Self {
        TreeBytes::zero()
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

    fn finish(self) -> arse_merkle_tree::H256 {
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
