//! The merkle tree in the storage

use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use ics23::ProofSpec;
use prost::Message;
use sha2::{Digest, Sha256};
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::error::Error as SmtError;
use sparse_merkle_tree::traits::Hasher;
use sparse_merkle_tree::{SparseMerkleTree, H256};
#[cfg(not(feature = "ABCI"))]
use tendermint::merkle::proof::{Proof, ProofOp};
#[cfg(feature = "ABCI")]
use tendermint_stable::merkle::proof::{Proof, ProofOp};
use thiserror::Error;

use crate::bytes::ByteBuf;
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::{DbKeySeg, Error as StorageError, Key};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid key: {0}")]
    InvalidKey(StorageError),
    #[error("Unexpected store type: {store_type}")]
    StoreType { store_type: StoreType },
    #[error("Empty Key: {0}")]
    EmptyKey(String),
    #[error("SMT error: {0}")]
    Smt(SmtError),
    #[error("Proof spec error")]
    InvalidProofSpec,
}

/// Result for functions that may fail
type Result<T> = std::result::Result<T, Error>;

#[derive(
    Clone,
    Copy,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum StoreType {
    Base,
    Account,
    PoS,
    Ibc,
}

impl StoreType {
    fn sub_tree_iter() -> std::slice::Iter<'static, Self> {
        static SUB_TREE_TYPES: [StoreType; 3] =
            [StoreType::Account, StoreType::PoS, StoreType::Ibc];
        SUB_TREE_TYPES.iter()
    }

    fn sub_key(key: &Key) -> Result<(Self, Key)> {
        if key.is_empty() {
            return Err(Error::EmptyKey("the key is empty".to_owned()));
        }
        match key.segments.get(0) {
            Some(DbKeySeg::AddressSeg(Address::Internal(internal))) => {
                match internal {
                    InternalAddress::PoS | InternalAddress::PosSlashPool => {
                        Ok((StoreType::PoS, key.sub_key()?))
                    }
                    InternalAddress::Ibc => {
                        Ok((StoreType::Ibc, key.sub_key()?))
                    }
                    // use the same key for Parameters
                    _ => Ok((StoreType::Account, key.clone())),
                }
            }
            // use the same key for Account
            _ => Ok((StoreType::Account, key.clone())),
        }
    }
}

impl fmt::Display for StoreType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreType::Base => write!(f, "base"),
            StoreType::Account => write!(f, "account"),
            StoreType::PoS => write!(f, "pos"),
            StoreType::Ibc => write!(f, "ibc"),
        }
    }
}

/// Merkle tree storage
pub struct MerkleTree<H: StorageHasher + Default> {
    base: SparseMerkleTree<H, H256, DefaultStore<H256>>,
    sub_trees:
        HashMap<StoreType, SparseMerkleTree<H, H256, DefaultStore<H256>>>,
}

impl<H: StorageHasher + Default> Default for MerkleTree<H> {
    fn default() -> Self {
        let mut sub_trees = HashMap::new();
        for st in StoreType::sub_tree_iter() {
            sub_trees.insert(
                *st,
                SparseMerkleTree::<H, H256, DefaultStore<H256>>::default(),
            );
        }
        Self {
            base: SparseMerkleTree::default(),
            sub_trees,
        }
    }
}

impl<H: StorageHasher + Default> core::fmt::Debug for MerkleTree<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let root_hash = format!("{}", ByteBuf(self.base.root().as_slice()));
        f.debug_struct("MerkleTree")
            .field("root_hash", &root_hash)
            .finish()
    }
}

impl<H: StorageHasher + Default> MerkleTree<H> {
    /// Restore the tree from the stores
    pub fn new(stores: MerkleTreeStores) -> Result<Self> {
        let mut sub_trees = HashMap::new();

        let (root, store) =
            stores.0.get(&StoreType::Base).ok_or(Error::StoreType {
                store_type: StoreType::Base,
            })?;
        let base = SparseMerkleTree::new(*root, store.clone());

        for st in StoreType::sub_tree_iter() {
            let (sub_root, store) = stores
                .0
                .get(st)
                .ok_or_else(|| Error::StoreType { store_type: *st })?;
            sub_trees.insert(
                *st,
                SparseMerkleTree::<H, H256, _>::new(*sub_root, store.clone()),
            );
        }

        Ok(Self { base, sub_trees })
    }

    /// Check if the key exists in the tree
    pub fn has_key(&self, key: &Key) -> Result<bool> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        match self.sub_trees.get(&store_type) {
            Some(smt) => {
                let value = smt.get(&H::hash(sub_key.to_string()))?;
                Ok(!value.is_zero())
            }
            None => Err(Error::StoreType { store_type }),
        }
    }

    /// Update the tree with the given key and value
    pub fn update(&mut self, key: &Key, value: impl AsRef<[u8]>) -> Result<()> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        match self.sub_trees.get_mut(&store_type) {
            Some(smt) => {
                let sub_root =
                    smt.update(H::hash(sub_key.to_string()), H::hash(value))?;
                let base_key = H::hash(&store_type.to_string());
                // update the base tree with the updated sub root
                self.base.update(base_key, *sub_root)?;
                Ok(())
            }
            None => Err(Error::StoreType { store_type }),
        }
    }

    /// Delete the value corresponding to the given key
    pub fn delete(&mut self, key: &Key) -> Result<()> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        match self.sub_trees.get_mut(&store_type) {
            Some(smt) => {
                let sub_root =
                    smt.update(H::hash(sub_key.to_string()), H256::zero())?;
                let base_key = H::hash(&store_type.to_string());
                // update the base tree with the updated sub root
                self.base.update(base_key, *sub_root)?;
                Ok(())
            }
            None => Err(Error::StoreType { store_type }),
        }
    }

    /// Get the root
    pub fn root(&self) -> MerkleRoot {
        (*self.base.root()).into()
    }

    /// Get the stores of the base and sub trees
    pub fn stores(&self) -> Result<MerkleTreeStores> {
        let mut stores = HashMap::new();
        stores.insert(
            StoreType::Base,
            (*self.base.root(), self.base.store().clone()),
        );
        for st in StoreType::sub_tree_iter() {
            let (sub_root, store) = match self.sub_trees.get(st) {
                Some(smt) => (*smt.root(), smt.store().clone()),
                None => return Err(Error::StoreType { store_type: *st }),
            };
            stores.insert(*st, (sub_root, store));
        }
        Ok(MerkleTreeStores(stores))
    }

    /// Get the proof
    pub fn get_proof(&self, key: &Key) -> Result<Proof> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        let smt = self
            .sub_trees
            .get(&store_type)
            .ok_or(Error::StoreType { store_type })?;

        // Get a proof of the sub tree
        let sub_key = H::hash(&sub_key.to_string());
        let sub_proof = if self.has_key(key)? {
            smt.membership_proof(&sub_key)?
        } else {
            smt.non_membership_proof(&sub_key)?
        };
        let mut data = vec![];
        sub_proof
            .encode(&mut data)
            .expect("Encoding proof shouldn't fail");
        let sub_proof_op = ProofOp {
            field_type: "ics23_CommitmentProof".to_string(),
            key: sub_key.as_slice().to_vec(),
            data,
        };

        // Get a membership proof of the base tree because the sub root should
        // exist
        let base_key = H::hash(&store_type.to_string());
        let base_proof = self.base.membership_proof(&base_key)?;
        let mut data = vec![];
        base_proof
            .encode(&mut data)
            .expect("Encoding proof shouldn't fail");
        let base_proof_op = ProofOp {
            field_type: "ics23_CommitmentProof".to_string(),
            key: base_key.as_slice().to_vec(),
            data,
        };

        // Set ProofOps from leaf to root
        Ok(Proof {
            ops: vec![sub_proof_op, base_proof_op],
        })
    }

    /// Get the proof spec
    pub fn proof_spec(&self) -> Result<ProofSpec> {
        let spec = sparse_merkle_tree::proof_ics23::get_spec(H::hash_op());
        // key and value has been hashed to be stored
        let leaf_spec = match spec.leaf_spec {
            Some(leaf_op) => ics23::LeafOp {
                prehash_key: H::hash_op().into(),
                prehash_value: H::hash_op().into(),
                ..leaf_op
            },
            None => return Err(Error::InvalidProofSpec),
        };
        Ok(ProofSpec {
            leaf_spec: Some(leaf_spec),
            ..spec
        })
    }
}

/// The root hash of the merkle tree as bytes
pub struct MerkleRoot(pub Vec<u8>);

impl From<H256> for MerkleRoot {
    fn from(root: H256) -> Self {
        Self(root.as_slice().to_vec())
    }
}

impl fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", ByteBuf(&self.0))
    }
}

/// The root and store pairs to be persistent
#[derive(BorshSerialize, BorshDeserialize)]
pub struct MerkleTreeStores(HashMap<StoreType, (H256, DefaultStore<H256>)>);

impl Default for MerkleTreeStores {
    fn default() -> Self {
        let mut stores = HashMap::new();
        stores.insert(
            StoreType::Base,
            (H256::default(), DefaultStore::default()),
        );
        for st in StoreType::sub_tree_iter() {
            stores.insert(*st, (H256::default(), DefaultStore::default()));
        }
        Self(stores)
    }
}

/// The storage hasher used for the merkle tree.
pub trait StorageHasher: Hasher + Default {
    /// Hash the value to store
    fn hash(value: impl AsRef<[u8]>) -> H256;
}

/// The storage hasher used for the merkle tree.
#[derive(Default)]
pub struct Sha256Hasher(sparse_merkle_tree::sha256::Sha256Hasher);

impl Hasher for Sha256Hasher {
    fn write_h256(&mut self, h: &H256) {
        self.0.write_h256(h)
    }

    fn finish(self) -> H256 {
        self.0.finish()
    }

    fn hash_op() -> ics23::HashOp {
        sparse_merkle_tree::sha256::Sha256Hasher::hash_op()
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

impl From<StorageError> for Error {
    fn from(error: StorageError) -> Self {
        Error::InvalidKey(error)
    }
}

impl From<SmtError> for Error {
    fn from(error: SmtError) -> Self {
        Error::Smt(error)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::storage::KeySeg;

    #[test]
    fn test_crud_value() {
        let mut tree = MerkleTree::<Sha256Hasher>::default();
        let key_prefix: Key =
            Address::Internal(InternalAddress::Ibc).to_db_key().into();
        let ibc_key = key_prefix.push(&"test".to_string()).unwrap();
        let key_prefix: Key =
            Address::Internal(InternalAddress::PoS).to_db_key().into();
        let pos_key = key_prefix.push(&"test".to_string()).unwrap();

        assert!(!tree.has_key(&ibc_key).unwrap());
        assert!(!tree.has_key(&pos_key).unwrap());

        // update IBC tree
        tree.update(&ibc_key, [1u8; 8].to_vec()).unwrap();
        assert!(tree.has_key(&ibc_key).unwrap());
        assert!(!tree.has_key(&pos_key).unwrap());
        // update another tree
        tree.update(&pos_key, [2u8; 8].to_vec()).unwrap();
        assert!(tree.has_key(&pos_key).unwrap());

        // delete a value on IBC tree
        tree.delete(&ibc_key).unwrap();
        assert!(!tree.has_key(&ibc_key).unwrap());
        assert!(tree.has_key(&pos_key).unwrap());
    }

    #[test]
    fn test_restore_tree() {
        let mut tree = MerkleTree::<Sha256Hasher>::default();

        let key_prefix: Key =
            Address::Internal(InternalAddress::Ibc).to_db_key().into();
        let ibc_key = key_prefix.push(&"test".to_string()).unwrap();
        let key_prefix: Key =
            Address::Internal(InternalAddress::PoS).to_db_key().into();
        let pos_key = key_prefix.push(&"test".to_string()).unwrap();

        tree.update(&ibc_key, [1u8; 8].to_vec()).unwrap();
        tree.update(&pos_key, [2u8; 8].to_vec()).unwrap();

        let stores = tree.stores().unwrap();
        let restored_tree = MerkleTree::<Sha256Hasher>::new(stores).unwrap();
        assert!(restored_tree.has_key(&ibc_key).unwrap());
        assert!(restored_tree.has_key(&pos_key).unwrap());
    }

    #[test]
    fn test_proof() {
        let mut tree = MerkleTree::<Sha256Hasher>::default();

        let key_prefix: Key =
            Address::Internal(InternalAddress::Ibc).to_db_key().into();
        let ibc_key = key_prefix.push(&"test".to_string()).unwrap();
        let key_prefix: Key =
            Address::Internal(InternalAddress::PoS).to_db_key().into();
        let pos_key = key_prefix.push(&"test".to_string()).unwrap();

        let ibc_val = [1u8; 8];
        tree.update(&ibc_key, ibc_val.to_vec()).unwrap();
        let pos_val = [2u8; 8];
        tree.update(&pos_key, pos_val.to_vec()).unwrap();

        let spec = tree.proof_spec().unwrap();
        let root = tree.root();
        let proof = tree.get_proof(&ibc_key).unwrap();
        for p in proof.ops.iter() {
            let commitment_proof =
                ics23::CommitmentProof::decode(&*p.data).unwrap();
            assert!(ics23::verify_membership(
                &commitment_proof,
                &spec,
                &root.0,
                ibc_key.to_string().as_bytes(),
                &ibc_val
            ));
        }
    }
}
