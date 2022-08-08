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
use itertools::Either;
use prost::Message;
use sha2::{Digest, Sha256};
use tendermint::merkle::proof::{Proof, ProofOp};
use thiserror::Error;

use super::IBC_KEY_LIMIT;
use crate::bytes::ByteBuf;
use crate::ledger::storage::types;
use crate::types::address::{Address, InternalAddress};
use crate::types::hash::Hash;
use crate::types::storage::{
    DbKeySeg, Error as StorageError, Key, MerkleKey, StringKey, TreeBytes,
};

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
    MerkleTree(MtError),
    #[error("Invalid store type: {0}")]
    StoreType(String),
    #[error("Non-existence proofs not supported for store type: {0}")]
    NonExistenceProof(String),
}

/// Result for functions that may fail
type Result<T> = std::result::Result<T, Error>;

/// Type aliases for the different merkle trees and backing stores
pub type SmtStore = DefaultStore<SmtHash, Hash, 32>;
pub type AmtStore = DefaultStore<StringKey, TreeBytes, IBC_KEY_LIMIT>;
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
}

impl Store {
    pub fn as_ref(&self) -> StoreRef {
        match self {
            Self::Base(store) => StoreRef::Base(store),
            Self::Account(store) => StoreRef::Account(store),
            Self::Ibc(store) => StoreRef::Ibc(store),
            Self::PoS(store) => StoreRef::PoS(store),
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
}

impl<'a> StoreRef<'a> {
    pub fn to_owned(&self) -> Store {
        match *self {
            Self::Base(store) => Store::Base(store.to_owned()),
            Self::Account(store) => Store::Account(store.to_owned()),
            Self::Ibc(store) => Store::Ibc(store.to_owned()),
            Self::PoS(store) => Store::PoS(store.to_owned()),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Base(store) => store.try_to_vec(),
            Self::Account(store) => store.try_to_vec(),
            Self::Ibc(store) => store.try_to_vec(),
            Self::PoS(store) => store.try_to_vec(),
        }
        .expect("Serialization failed")
    }
}

impl StoreType {
    /// Get an iterator for the base tree and subtrees
    pub fn iter() -> std::slice::Iter<'static, Self> {
        static SUB_TREE_TYPES: [StoreType; 4] = [
            StoreType::Base,
            StoreType::Account,
            StoreType::PoS,
            StoreType::Ibc,
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

        Self {
            base,
            account,
            ibc,
            pos,
        }
    }

    fn tree(&self, store_type: &StoreType) -> Either<&Smt<H>, &Amt<H>> {
        match store_type {
            StoreType::Base => Either::Left(&self.base),
            StoreType::Account => Either::Left(&self.account),
            StoreType::Ibc => Either::Right(&self.ibc),
            StoreType::PoS => Either::Left(&self.pos),
        }
    }

    fn update_tree(
        &mut self,
        store_type: &StoreType,
        key: MerkleKey<H>,
        value: Either<Hash, TreeBytes>,
    ) -> Result<()> {
        let sub_root = match store_type {
            StoreType::Account => self
                .account
                .update(key.try_into()?, value.unwrap_left())
                .map_err(Error::MerkleTree)?,
            StoreType::Ibc => self
                .ibc
                .update(key.try_into()?, value.unwrap_right())
                .map_err(Error::MerkleTree)?,
            StoreType::PoS => self
                .pos
                .update(key.try_into()?, value.unwrap_left())
                .map_err(Error::MerkleTree)?,
            // base tree should not be directly updated
            StoreType::Base => unreachable!(),
        };

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
        let value = match self.tree(&store_type) {
            Either::Left(smt) => {
                smt.get(&H::hash(sub_key.to_string()).into())?.is_zero()
            }
            Either::Right(amt) => {
                let key =
                    StringKey::try_from_bytes(sub_key.to_string().as_bytes())?;
                amt.get(&key)?.is_zero()
            }
        };
        Ok(!value)
    }

    /// Update the tree with the given key and value
    pub fn update(&mut self, key: &Key, value: impl AsRef<[u8]>) -> Result<()> {
        let sub_key = StoreType::sub_key(key)?;
        let store_type = sub_key.0;
        let value = match store_type {
            StoreType::Ibc => {
                Either::Right(TreeBytes::from(value.as_ref().to_vec()))
            }
            _ => Either::Left(H::hash(value).into()),
        };
        self.update_tree(&store_type, sub_key.into(), value)
    }

    /// Delete the value corresponding to the given key
    pub fn delete(&mut self, key: &Key) -> Result<()> {
        let sub_key = StoreType::sub_key(key)?;
        let store_type = sub_key.0;
        let value = match store_type {
            StoreType::Ibc => Either::Right(TreeBytes::zero()),
            _ => Either::Left(H256::zero().into()),
        };
        self.update_tree(&store_type, sub_key.into(), value)
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
                            value,
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

impl<H: StorageHasher> From<(StoreType, Key)> for MerkleKey<H> {
    fn from((store, key): (StoreType, Key)) -> Self {
        match store {
            StoreType::Base | StoreType::Account | StoreType::PoS => {
                MerkleKey::Sha256(key, PhantomData)
            }
            StoreType::Ibc => MerkleKey::Raw(key),
        }
    }
}

impl<H: StorageHasher> TryFrom<MerkleKey<H>> for SmtHash {
    type Error = Error;

    fn try_from(value: MerkleKey<H>) -> Result<Self> {
        match value {
            MerkleKey::Sha256(key, _) => Ok(H::hash(key.to_string()).into()),
            _ => Err(Error::InvalidMerkleKey(
                "This key is for a sparse merkle tree".into(),
            )),
        }
    }
}

impl<H: StorageHasher> TryFrom<MerkleKey<H>> for StringKey {
    type Error = Error;

    fn try_from(value: MerkleKey<H>) -> Result<Self> {
        match value {
            MerkleKey::Raw(key) => {
                Self::try_from_bytes(key.to_string().as_bytes())
            }
            _ => Err(Error::InvalidMerkleKey(
                "This is not an key for the IBC subtree".into(),
            )),
        }
    }
}

/// The root and store pairs to restore the trees
#[derive(Default)]
pub struct MerkleTreeStoresRead {
    base: (Hash, SmtStore),
    account: (Hash, SmtStore),
    ibc: (Hash, AmtStore),
    pos: (Hash, SmtStore),
}

impl MerkleTreeStoresRead {
    /// Set the root of the given store type
    pub fn set_root(&mut self, store_type: &StoreType, root: Hash) {
        match store_type {
            StoreType::Base => self.base.0 = root,
            StoreType::Account => self.account.0 = root,
            StoreType::Ibc => self.ibc.0 = root,
            StoreType::PoS => self.pos.0 = root,
        }
    }

    /// Set the store of the given store type
    pub fn set_store(&mut self, store_type: Store) {
        match store_type {
            Store::Base(store) => self.base.1 = store,
            Store::Account(store) => self.account.1 = store,
            Store::Ibc(store) => self.ibc.1 = store,
            Store::PoS(store) => self.pos.1 = store,
        }
    }
}

/// The root and store pairs to be persistent
pub struct MerkleTreeStoresWrite<'a> {
    base: (Hash, &'a SmtStore),
    account: (Hash, &'a SmtStore),
    ibc: (Hash, &'a AmtStore),
    pos: (Hash, &'a SmtStore),
}

impl<'a> MerkleTreeStoresWrite<'a> {
    /// Get the root of the given store type
    pub fn root(&self, store_type: &StoreType) -> &Hash {
        match store_type {
            StoreType::Base => &self.base.0,
            StoreType::Account => &self.account.0,
            StoreType::Ibc => &self.ibc.0,
            StoreType::PoS => &self.pos.0,
        }
    }

    /// Get the store of the given store type
    pub fn store(&self, store_type: &StoreType) -> StoreRef {
        match store_type {
            StoreType::Base => StoreRef::Base(self.base.1),
            StoreType::Account => StoreRef::Account(self.account.1),
            StoreType::Ibc => StoreRef::Ibc(self.ibc.1),
            StoreType::PoS => StoreRef::PoS(self.pos.1),
        }
    }
}

impl TreeKey<IBC_KEY_LIMIT> for StringKey {
    type Error = Error;

    fn as_slice(&self) -> &[u8] {
        &self.original.as_slice()[..self.length]
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
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
