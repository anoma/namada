//! The merkle tree in the storage
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use arse_merkle_tree::default_store::DefaultStore;
use arse_merkle_tree::error::Error as MtError;
use arse_merkle_tree::traits::{Hasher, Value};
use arse_merkle_tree::{
    Hash as SmtHash, Key as TreeKey, SparseMerkleTree as ArseMerkleTree, H256,
};
use borsh::{BorshDeserialize, BorshSerialize};
use ics23::commitment_proof::Proof as Ics23Proof;
use ics23::{
    CommitmentProof, ExistenceProof, HashOp, LeafOp, LengthOp,
    NonExistenceProof, ProofSpec,
};
use itertools::{Either, Itertools};
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::IBC_KEY_LIMIT;
use super::traits::{self, StorageHasher, Sha256Hasher};
use crate::bytes::ByteBuf;
use crate::ledger::eth_bridge::storage::bridge_pool::BridgePoolTree;
use crate::ledger::storage::types;
use crate::tendermint::merkle::proof::{Proof, ProofOp};
use crate::types::address::{Address, InternalAddress};
use crate::types::eth_bridge_pool::{PendingTransfer, TransferToEthereum};
use crate::types::ethereum_events::KeccakHash;
use crate::types::hash::Hash;
use crate::types::storage::{DbKeySeg, Error as StorageError, Key, StringKey, TreeBytes, MerkleValue};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid key: {0}")]
    InvalidKey(StorageError),
    #[error("Invalid key for merkle tree: {0}")]
    InvalidMerkleKey(String),
    #[error("Empty Key: {0}")]
    EmptyKey(String),
    #[error("Merkle Tree error: {0}")]
    MerkleTree(String),
    #[error("Invalid store type: {0}")]
    StoreType(String),
    #[error("Non-existence proofs not supported for store type: {0}")]
    NonExistenceProof(String),
    #[error("Invalid value given to sub-tree storage")]
    InvalidValue,
}

/// Result for functions that may fail
type Result<T> = std::result::Result<T, Error>;

/// Type aliases for the different merkle trees and backing stores
pub type SmtStore = DefaultStore<SmtHash, Hash, 32>;
pub type AmtStore = DefaultStore<StringKey, TreeBytes, IBC_KEY_LIMIT>;
pub type BridgePoolStore = std::collections::BTreeMap<KeccakHash, PendingTransfer>;
pub type Smt<H> = ArseMerkleTree<H, SmtHash, Hash, SmtStore, 32>;
pub type Amt<H> =
    ArseMerkleTree<H, StringKey, TreeBytes, AmtStore, IBC_KEY_LIMIT>;

/// Store types for the merkle tree
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
    /// Base tree, which has roots of the subtrees
    Base,
    /// For Account and other data
    Account,
    /// For IBC-related data
    Ibc,
    /// For PoS-related data
    PoS,
    /// For the Ethereum bridge Pool transfers
    BridgePool,
}

/// Backing storage for merkle trees
pub enum Store {
    /// Base tree, which has roots of the subtrees
    Base(SmtStore),
    /// For Account and other data
    Account(SmtStore),
    /// For IBC-related data
    Ibc(AmtStore),
    /// For PoS-related data
    PoS(SmtStore),
    /// For the Ethereum bridge Pool transfers
    BridgePool(BTreeSetStore)
}

impl Store {
    pub fn as_ref(&self) -> StoreRef {
        match self {
            Self::Base(store) => StoreRef::Base(store),
            Self::Account(store) => StoreRef::Account(store),
            Self::Ibc(store) => StoreRef::Ibc(store),
            Self::PoS(store) => StoreRef::PoS(store),
            Self::BridgePool(store) => StoreRef::BridgePool(store),
        }
    }
}

/// Pointer to backing storage of merkle tree
pub enum StoreRef<'a> {
    /// Base tree, which has roots of the subtrees
    Base(&'a SmtStore),
    /// For Account and other data
    Account(&'a SmtStore),
    /// For IBC-related data
    Ibc(&'a AmtStore),
    /// For PoS-related data
    PoS(&'a SmtStore),
    /// For the Ethereum bridge Pool transfers
    BridgePool(&'a BTreeSetStore)
}

impl<'a> StoreRef<'a> {
    pub fn to_owned(&self) -> Store {
        match *self {
            Self::Base(store) => Store::Base(store.to_owned()),
            Self::Account(store) => Store::Account(store.to_owned()),
            Self::Ibc(store) => Store::Ibc(store.to_owned()),
            Self::PoS(store) => Store::PoS(store.to_owned()),
            Self::BridgePool(store) => Store::BridgePool(store.to_owned()),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Base(store) => store.try_to_vec(),
            Self::Account(store) => store.try_to_vec(),
            Self::Ibc(store) => store.try_to_vec(),
            Self::PoS(store) => store.try_to_vec(),
            Self::BridgePool(store) => store.try_to_vec(),
        }
        .expect("Serialization failed")
    }
}

impl StoreType {
    /// Get an iterator for the base tree and subtrees
    pub fn iter() -> std::slice::Iter<'static, Self> {
        static SUB_TREE_TYPES: [StoreType; 5] = [
            StoreType::Base,
            StoreType::Account,
            StoreType::PoS,
            StoreType::Ibc,
            StoreType::BridgePool,
        ];
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
                    InternalAddress::EthBridgePool => {
                        Ok((StoreType::BridgePool, key.sub_key()?))
                    }
                    // use the same key for Parameters
                    _ => Ok((StoreType::Account, key.clone())),
                }
            }
            // use the same key for Account
            _ => Ok((StoreType::Account, key.clone())),
        }
    }

    /// Decode the backing store from bytes and tag its type correctly
    pub fn decode_store<T: AsRef<[u8]>>(
        &self,
        bytes: T,
    ) -> std::result::Result<Store, super::Error> {
        use super::Error;
        match self {
            Self::Base => Ok(Store::Base(
                types::decode(bytes).map_err(Error::CodingError)?,
            )),
            Self::Account => Ok(Store::Account(
                types::decode(bytes).map_err(Error::CodingError)?,
            )),
            Self::Ibc => Ok(Store::Ibc(
                types::decode(bytes).map_err(Error::CodingError)?,
            )),
            Self::PoS => Ok(Store::PoS(
                types::decode(bytes).map_err(Error::CodingError)?,
            )),
            Self::BridgePool => Ok(Store::BridgePool(
                types::decode(bytes).map_err(Error::CodingError)?,
            )),
        }
    }
}

impl FromStr for StoreType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "base" => Ok(StoreType::Base),
            "account" => Ok(StoreType::Account),
            "ibc" => Ok(StoreType::Ibc),
            "pos" => Ok(StoreType::PoS),
            "eth_bridge_pool" => Ok(StoreType::BridgePool),
            _ => Err(Error::StoreType(s.to_string())),
        }
    }
}

impl fmt::Display for StoreType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreType::Base => write!(f, "base"),
            StoreType::Account => write!(f, "account"),
            StoreType::Ibc => write!(f, "ibc"),
            StoreType::PoS => write!(f, "pos"),
            StoreType::BridgePool => write!(f, "eth_bridge_pool"),
        }
    }
}

/// Merkle tree storage
#[derive(Default)]
pub struct MerkleTree<H: StorageHasher + Default> {
    base: Smt<H>,
    account: Smt<H>,
    ibc: Amt<H>,
    pos: Smt<H>,
    bridge_pool: BridgePoolTree,
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
    pub fn new(stores: MerkleTreeStoresRead) -> Self {
        let base = Smt::new(stores.base.0.into(), stores.base.1);
        let account = Smt::new(stores.account.0.into(), stores.account.1);
        let ibc = Amt::new(stores.ibc.0.into(), stores.ibc.1);
        let pos = Smt::new(stores.pos.0.into(), stores.pos.1);
        let bridge_pool = BridgePoolTree::new(stores.bridge_pool.0, stores.bridge_pool.1);
        Self {
            base,
            account,
            ibc,
            pos,
            bridge_pool,
        }
    }

    fn tree(&self, store_type: &StoreType) -> &impl traits::MerkleTree {
        match store_type {
            StoreType::Base => &self.base,
            StoreType::Account => &self.account,
            StoreType::Ibc => &self.ibc,
            StoreType::PoS => &self.pos,
            StoreType::BridgePool => &self.bridge_pool,
        }
    }

    fn tree_mut(&mut self, store_type: &StoreType) -> &mut impl traits::MerkleTree {
        match store_type {
            StoreType::Base => &mut self.base,
            StoreType::Account => &mut self.account,
            StoreType::Ibc => &mut self.ibc,
            StoreType::PoS => &mut self.pos,
            StoreType::BridgePool => &mut self.bridge_pool,
        }
    }

    fn update_tree<T: AsRef<[u8]>>(
        &mut self,
        store_type: &StoreType,
        key: &Key,
        value: MerkleValue<T>,
    ) -> Result<()> {
        let sub_root = self.tree_mut(store_type).update(key, value)?;
        // update the base tree with the updated sub root without hashing
        if *store_type != StoreType::Base {
            let base_key = H::hash(&store_type.to_string());
            self.base.update(base_key.into(), Hash::from(sub_root))?;
        }
        Ok(())
    }

    /// Check if the key exists in the tree
    pub fn has_key(&self, key: &Key) -> Result<bool> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        self.tree(&store_type).has_key(&sub_key)
    }

    /// Update the tree with the given key and value
    pub fn update<T: AsRef<[u8]>>(&mut self, key: &Key, value: impl Into<MerkleValue<T>>) -> Result<()> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        self.update_tree(&store_type, sub_key.into(), value.into())
    }

    /// Delete the value corresponding to the given key
    pub fn delete(&mut self, key: &Key) -> Result<()> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        self.tree_mut(&store_type).delete(&sub_key)
    }

    /// Get the root
    pub fn root(&self) -> MerkleRoot {
        self.base.root().into()
    }

    /// Get the stores of the base and sub trees
    pub fn stores(&self) -> MerkleTreeStoresWrite {
        MerkleTreeStoresWrite {
            base: (self.base.root().into(), self.base.store()),
            account: (self.account.root().into(), self.account.store()),
            ibc: (self.ibc.root().into(), self.ibc.store()),
            pos: (self.pos.root().into(), self.pos.store()),
            bridge_pool: (self.bridge_pool.root(). self.)
        }
    }

    /// Get the existence proof
    pub fn get_existence_proof(
        &self,
        key: &Key,
        value: Vec<u8>,
    ) -> Result<Proof> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        let sub_proof = match self.tree(&store_type) {
            Either::Left(smt) => {
                let cp = smt
                    .membership_proof(&H::hash(&sub_key.to_string()).into())?;
                // Replace the values and the leaf op for the verification
                match cp.proof.expect("The proof should exist") {
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
                }
            }
            Either::Right(amt) => {
                let key =
                    StringKey::try_from_bytes(sub_key.to_string().as_bytes())?;
                let cp = amt.membership_proof(&key)?;

                // Replace the values and the leaf op for the verification
                match cp.proof.expect("The proof should exist") {
                    Ics23Proof::Exist(ep) => CommitmentProof {
                        proof: Some(Ics23Proof::Exist(ExistenceProof {
                            leaf: Some(self.ibc_leaf_spec()),
                            ..ep
                        })),
                    },
                    _ => unreachable!(),
                }
            }
        };
        self.get_proof(key, sub_proof)
    }

    /// Get the non-existence proof
    pub fn get_non_existence_proof(&self, key: &Key) -> Result<Proof> {
        let (store_type, sub_key) = StoreType::sub_key(key)?;
        let sub_proof = match self.tree(&store_type) {
            Either::Left(_) => {
                return Err(Error::NonExistenceProof(store_type.to_string()));
            }
            Either::Right(amt) => {
                let key =
                    StringKey::try_from_bytes(sub_key.to_string().as_bytes())?;
                let mut nep = amt.non_membership_proof(&key)?;
                // Replace the values and the leaf op for the verification
                if let Some(ref mut nep) = nep.proof {
                    match nep {
                        Ics23Proof::Nonexist(ref mut ep) => {
                            let NonExistenceProof {
                                ref mut left,
                                ref mut right,
                                ..
                            } = ep;
                            let ep = left.as_mut().or(right.as_mut()).expect(
                                "A left or right existence proof should exist.",
                            );
                            ep.leaf = Some(self.ibc_leaf_spec());
                        }
                        _ => unreachable!(),
                    }
                }
                nep
            }
        };
        // Get a proof of the sub tree
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
        let cp = self.base.membership_proof(&H::hash(&base_key).into())?;
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
        let spec = arse_merkle_tree::proof_ics23::get_spec(H::hash_op());
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

    /// Get the proof specs for ibc
    pub fn ibc_proof_specs(&self) -> Vec<ProofSpec> {
        let spec = arse_merkle_tree::proof_ics23::get_spec(H::hash_op());
        let sub_tree_spec = ProofSpec {
            leaf_spec: Some(self.ibc_leaf_spec()),
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

    /// Get the leaf spec for the ibc subtree. Non-hashed values are used for
    /// the verification with this spec because a subtree stores the
    /// key-value pairs after hashing. However, keys are also not hashed in
    /// the backing store.
    fn ibc_leaf_spec(&self) -> LeafOp {
        LeafOp {
            hash: H::hash_op().into(),
            prehash_key: HashOp::NoHash.into(),
            prehash_value: HashOp::NoHash.into(),
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

impl From<&H256> for MerkleRoot {
    fn from(root: &H256) -> Self {
        let root = *root;
        Self(root.as_slice().to_vec())
    }
}

impl fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", ByteBuf(&self.0))
    }
}

/// The root and store pairs to restore the trees
#[derive(Default)]
pub struct MerkleTreeStoresRead {
    base: (Hash, SmtStore),
    account: (Hash, SmtStore),
    ibc: (Hash, AmtStore),
    pos: (Hash, SmtStore),
    bridge_pool: (KeccakHash, BTreeSetStore),
}

impl MerkleTreeStoresRead {
    /// Set the root of the given store type
    pub fn set_root(&mut self, store_type: &StoreType, root: Hash) {
        match store_type {
            StoreType::Base => self.base.0 = root,
            StoreType::Account => self.account.0 = root,
            StoreType::Ibc => self.ibc.0 = root,
            StoreType::PoS => self.pos.0 = root,
            StoreType::BridgePool => self.bridge_pool.0 = root.into(),
        }
    }

    /// Set the store of the given store type
    pub fn set_store(&mut self, store_type: Store) {
        match store_type {
            Store::Base(store) => self.base.1 = store,
            Store::Account(store) => self.account.1 = store,
            Store::Ibc(store) => self.ibc.1 = store,
            Store::PoS(store) => self.pos.1 = store,
            Store::BridgePool(store) => self.bridge_pool.1 = store,
        }
    }
}

/// The root and store pairs to be persistent
pub struct MerkleTreeStoresWrite<'a> {
    base: (Hash, &'a SmtStore),
    account: (Hash, &'a SmtStore),
    ibc: (Hash, &'a AmtStore),
    pos: (Hash, &'a SmtStore),
    bridge_pool: (Hash, &'a BTreeSetStore)
}

impl<'a> MerkleTreeStoresWrite<'a> {
    /// Get the root of the given store type
    pub fn root(&self, store_type: &StoreType) -> &Hash {
        match store_type {
            StoreType::Base => &self.base.0,
            StoreType::Account => &self.account.0,
            StoreType::Ibc => &self.ibc.0,
            StoreType::PoS => &self.pos.0,
            StoreType::BridgePool => &self.bridge_pool.0
        }
    }

    /// Get the store of the given store type
    pub fn store(&self, store_type: &StoreType) -> StoreRef {
        match store_type {
            StoreType::Base => StoreRef::Base(self.base.1),
            StoreType::Account => StoreRef::Account(self.account.1),
            StoreType::Ibc => StoreRef::Ibc(self.ibc.1),
            StoreType::PoS => StoreRef::PoS(self.pos.1),
            StoreType::BridgePool => StoreRef::BridgePool(self.bridge_pool.1)
        }
    }
}


impl From<StorageError> for Error {
    fn from(error: StorageError) -> Self {
        Error::InvalidKey(error)
    }
}

impl From<MtError> for Error {
    fn from(error: MtError) -> Self {
        Error::MerkleTree(error)
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
        tree.update(&ibc_key, [1u8; 8]).unwrap();
        assert!(tree.has_key(&ibc_key).unwrap());
        assert!(!tree.has_key(&pos_key).unwrap());
        // update another tree
        tree.update(&pos_key, [2u8; 8]).unwrap();
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

        tree.update(&ibc_key, [1u8; 8]).unwrap();
        tree.update(&pos_key, [2u8; 8]).unwrap();

        let stores_write = tree.stores();
        let mut stores_read = MerkleTreeStoresRead::default();
        for st in StoreType::iter() {
            stores_read.set_root(st, stores_write.root(st).clone());
            stores_read.set_store(stores_write.store(st).to_owned());
        }
        let restored_tree = MerkleTree::<Sha256Hasher>::new(stores_read);
        assert!(restored_tree.has_key(&ibc_key).unwrap());
        assert!(restored_tree.has_key(&pos_key).unwrap());
    }

    #[test]
    fn test_ibc_existence_proof() {
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

        let specs = tree.ibc_proof_specs();
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

    #[test]
    fn test_non_ibc_existence_proof() {
        let mut tree = MerkleTree::<Sha256Hasher>::default();

        let key_prefix: Key =
            Address::Internal(InternalAddress::Ibc).to_db_key().into();
        let ibc_key = key_prefix.push(&"test".to_string()).unwrap();
        let key_prefix: Key =
            Address::Internal(InternalAddress::PoS).to_db_key().into();
        let pos_key = key_prefix.push(&"test".to_string()).unwrap();

        let ibc_val = [1u8; 8].to_vec();
        tree.update(&ibc_key, ibc_val).unwrap();
        let pos_val = [2u8; 8].to_vec();
        tree.update(&pos_key, pos_val.clone()).unwrap();

        let specs = tree.proof_specs();
        let proof =
            tree.get_existence_proof(&pos_key, pos_val.clone()).unwrap();
        let (store_type, sub_key) = StoreType::sub_key(&pos_key).unwrap();
        let paths = vec![sub_key.to_string(), store_type.to_string()];
        let mut sub_root = pos_val.clone();
        let mut value = pos_val;
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

    #[test]
    fn test_ibc_non_existence_proof() {
        let mut tree = MerkleTree::<Sha256Hasher>::default();

        let key_prefix: Key =
            Address::Internal(InternalAddress::Ibc).to_db_key().into();
        let ibc_non_key =
            key_prefix.push(&"test".to_string()).expect("Test failed");
        let key_prefix: Key =
            Address::Internal(InternalAddress::Ibc).to_db_key().into();
        let ibc_key =
            key_prefix.push(&"test2".to_string()).expect("Test failed");
        let ibc_val = [2u8; 8].to_vec();
        tree.update(&ibc_key, ibc_val).expect("Test failed");

        let nep = tree
            .get_non_existence_proof(&ibc_non_key)
            .expect("Test failed");
        let subtree_nep = nep.ops.get(0).expect("Test failed");
        let nep_commitment_proof =
            CommitmentProof::decode(&*subtree_nep.data).expect("Test failed");
        let non_existence_proof =
            match nep_commitment_proof.clone().proof.expect("Test failed") {
                Ics23Proof::Nonexist(nep) => nep,
                _ => unreachable!(),
            };
        let subtree_root = if let Some(left) = &non_existence_proof.left {
            ics23::calculate_existence_root(left).unwrap()
        } else if let Some(right) = &non_existence_proof.right {
            ics23::calculate_existence_root(right).unwrap()
        } else {
            unreachable!()
        };
        let (store_type, sub_key) =
            StoreType::sub_key(&ibc_non_key).expect("Test failed");
        let specs = tree.ibc_proof_specs();

        let nep_verification_res = ics23::verify_non_membership(
            &nep_commitment_proof,
            &specs[0],
            &subtree_root,
            sub_key.to_string().as_bytes(),
        );
        assert!(nep_verification_res);
        let basetree_ep = nep.ops.get(1).unwrap();
        let basetree_ep_commitment_proof =
            CommitmentProof::decode(&*basetree_ep.data).unwrap();
        let basetree_ics23_ep =
            match basetree_ep_commitment_proof.clone().proof.unwrap() {
                Ics23Proof::Exist(ep) => ep,
                _ => unreachable!(),
            };
        let basetree_root =
            ics23::calculate_existence_root(&basetree_ics23_ep).unwrap();
        let basetree_verification_res = ics23::verify_membership(
            &basetree_ep_commitment_proof,
            &specs[1],
            &basetree_root,
            store_type.to_string().as_bytes(),
            &subtree_root,
        );
        assert!(basetree_verification_res);
    }
}
