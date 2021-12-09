//! The merkle tree in the storage

use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use ics23::commitment_proof::Proof as Ics23Proof;
use ics23::{
    CommitmentProof, ExistenceProof, HashOp, LeafOp, LengthOp,
    NonExistenceProof, ProofSpec,
};
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
    subtrees: HashMap<StoreType, SparseMerkleTree<H, H256, DefaultStore<H256>>>,
}

impl<H: StorageHasher + Default> Default for MerkleTree<H> {
    fn default() -> Self {
        let mut subtrees = HashMap::new();
        for st in StoreType::sub_tree_iter() {
            subtrees.insert(
                *st,
                SparseMerkleTree::<H, H256, DefaultStore<H256>>::default(),
            );
        }
        Self {
            base: SparseMerkleTree::default(),
            subtrees,
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
        let mut subtrees = HashMap::new();

        let (root, store) = stores
            .0
            .get(&StoreType::Base)
            .expect("The base tree should exist");
        let base = SparseMerkleTree::new(*root, store.clone());

        for st in StoreType::sub_tree_iter() {
            let (sub_root, store) =
                stores.0.get(st).expect("The subtree should exist");
            subtrees.insert(
                *st,
                SparseMerkleTree::<H, H256, _>::new(*sub_root, store.clone()),
            );
        }

        Ok(Self { base, subtrees })
    }

    /// Check if the key exists in the tree
    pub fn has_key(&self, key: &Key) -> Result<bool> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        let subtree = self
            .subtrees
            .get(&store_type)
            .expect("The subtree should exist");
        let value = subtree.get(&H::hash(sub_key.to_string()))?;
        Ok(!value.is_zero())
    }

    /// Update the tree with the given key and value
    pub fn update(&mut self, key: &Key, value: impl AsRef<[u8]>) -> Result<()> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        let subtree = self
            .subtrees
            .get_mut(&store_type)
            .expect("The subtree should exist");
        let sub_root = subtree
            .update(H::hash(sub_key.to_string()), H::hash(value))?;

        let base_key = H::hash(&store_type.to_string());
        // update the base tree with the updated sub root without hashing
        self.base.update(base_key, *sub_root)?;
        Ok(())
    }

    /// Delete the value corresponding to the given key
    pub fn delete(&mut self, key: &Key) -> Result<()> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        let subtree = self
            .subtrees
            .get_mut(&store_type)
            .expect("The subtree should exist");
        let sub_root =
            subtree.update(H::hash(sub_key.to_string()), H256::zero())?;

        let base_key = H::hash(&store_type.to_string());
        // update the base tree with the updated sub root without hashing
        self.base.update(base_key, *sub_root)?;
        Ok(())
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
            let subtree =
                self.subtrees.get(st).expect("The subtree should exist");
            stores.insert(*st, (*subtree.root(), subtree.store().clone()));
        }
        Ok(MerkleTreeStores(stores))
    }

    /// Get the existence proof
    pub fn get_existence_proof(
        &self,
        key: &Key,
        value: Vec<u8>,
    ) -> Result<Proof> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        let subtree = self
            .subtrees
            .get(&store_type)
            .expect("The subtree should exist");

        // Get a proof of the sub tree
        let hashed_sub_key = H::hash(&sub_key.to_string());
        let cp = subtree.membership_proof(&hashed_sub_key)?;
        // Replace the values and the leaf op for the verification
        let sub_proof = match cp.proof.expect("The proof should exist") {
            Ics23Proof::Exist(ep) => CommitmentProof {
                proof: Some(Ics23Proof::Exist(ExistenceProof {
                    key: sub_key.to_string().as_bytes().to_vec(),
                    value,
                    leaf: Some(self.leaf_spec()),
                    ..ep
                })),
            },
            // the proof should have an ExistenceProof
            _ => unreachable!(),
        };
        self.get_proof(key, sub_proof)
    }

    /// Get the non-existence proof
    pub fn get_non_existence_proof(&self, key: &Key) -> Result<Proof> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        let subtree = self
            .subtrees
            .get(&store_type)
            .expect("The subtree should exist");

        // Get a proof of the sub tree
        let hashed_sub_key = H::hash(&sub_key.to_string());
        let cp = subtree.non_membership_proof(&hashed_sub_key)?;
        // Replace the key with the non-hashed key for the verification
        let sub_proof = match cp.proof.expect("The proof should exist") {
            Ics23Proof::Nonexist(nep) => CommitmentProof {
                proof: Some(Ics23Proof::Nonexist(NonExistenceProof {
                    key: sub_key.to_string().as_bytes().to_vec(),
                    ..nep
                })),
            },
            // the proof should have a NonExistenceProof
            _ => unreachable!(),
        };
        self.get_proof(key, sub_proof)
    }

    /// Get the Tendermint proof with the base proof
    fn get_proof(
        &self,
        key: &Key,
        sub_proof: CommitmentProof,
    ) -> Result<Proof> {
        let mut data = vec![];
        sub_proof
            .encode(&mut data)
            .expect("Encoding proof shouldn't fail");
        let sub_proof_op = ProofOp {
            field_type: "ics23_CommitmentProof".to_string(),
            key: key.to_string().as_bytes().to_vec(),
            data,
        };

        // Get a membership proof of the base tree because the sub root should
        // exist
        let (store_type, _) = StoreType::sub_key(key)?;
        let base_key = store_type.to_string();
        let cp = self.base.membership_proof(&H::hash(&base_key))?;
        // Replace the values and the leaf op for the verification
        let base_proof = match cp.proof.expect("The proof should exist") {
            Ics23Proof::Exist(ep) => CommitmentProof {
                proof: Some(Ics23Proof::Exist(ExistenceProof {
                    key: base_key.as_bytes().to_vec(),
                    leaf: Some(self.base_leaf_spec()),
                    ..ep
                })),
            },
            // the proof should have an ExistenceProof
            _ => unreachable!(),
        };

        let mut data = vec![];
        base_proof
            .encode(&mut data)
            .expect("Encoding proof shouldn't fail");
        let base_proof_op = ProofOp {
            field_type: "ics23_CommitmentProof".to_string(),
            key: key.to_string().as_bytes().to_vec(),
            data,
        };

        // Set ProofOps from leaf to root
        Ok(Proof {
            ops: vec![sub_proof_op, base_proof_op],
        })
    }

    /// Get the proof specs
    pub fn proof_specs(&self) -> Vec<ProofSpec> {
        let spec = sparse_merkle_tree::proof_ics23::get_spec(H::hash_op());
        let sub_tree_spec = ProofSpec {
            leaf_spec: Some(self.leaf_spec()),
            ..spec.clone()
        };
        let base_tree_spec = ProofSpec {
            leaf_spec: Some(self.base_leaf_spec()),
            ..spec
        };
        vec![sub_tree_spec, base_tree_spec]
    }

    /// Get the leaf spec for the base tree. The key is stored after hashing,
    /// but the stored value is the subtree's root without hashing.
    fn base_leaf_spec(&self) -> LeafOp {
        LeafOp {
            hash: H::hash_op().into(),
            prehash_key: H::hash_op().into(),
            prehash_value: HashOp::NoHash.into(),
            length: LengthOp::NoPrefix.into(),
            prefix: H256::zero().as_slice().to_vec(),
        }
    }

    /// Get the leaf spec for the subtree. Non-hashed values are used for the
    /// verification with this spec because a subtree stores the key-value pairs
    /// after hashing.
    fn leaf_spec(&self) -> LeafOp {
        LeafOp {
            hash: H::hash_op().into(),
            prehash_key: H::hash_op().into(),
            prehash_value: H::hash_op().into(),
            length: LengthOp::NoPrefix.into(),
            prefix: H256::zero().as_slice().to_vec(),
        }
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

        let ibc_val = [1u8; 8].to_vec();
        tree.update(&ibc_key, ibc_val.clone()).unwrap();
        let pos_val = [2u8; 8].to_vec();
        tree.update(&pos_key, pos_val).unwrap();

        let specs = tree.proof_specs();
        let proof =
            tree.get_existence_proof(&ibc_key, ibc_val.clone()).unwrap();
        let (store_type, sub_key) = StoreType::sub_key(&ibc_key).unwrap();
        let paths = vec![sub_key.to_string(), store_type.to_string()];
        let mut sub_root = ibc_val.clone();
        let mut value = ibc_val;
        // First, the sub proof is verified. Next the base proof is verified
        // with the sub root
        for ((p, spec), key) in
            proof.ops.iter().zip(specs.iter()).zip(paths.iter())
        {
            let commitment_proof = CommitmentProof::decode(&*p.data).unwrap();
            let existence_proof = match commitment_proof.clone().proof.unwrap()
            {
                Ics23Proof::Exist(ep) => ep,
                _ => unreachable!(),
            };
            sub_root =
                ics23::calculate_existence_root(&existence_proof).unwrap();
            assert!(ics23::verify_membership(
                &commitment_proof,
                spec,
                &sub_root,
                key.as_bytes(),
                &value,
            ));
            // for the verification of the base tree
            value = sub_root.clone();
        }
        // Check the base root
        assert_eq!(sub_root, tree.root().0);
    }
}
