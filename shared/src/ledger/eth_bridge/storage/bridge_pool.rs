//! Tools for accessing the storage subspaces of the Ethereum
//! bridge pool
use std::collections::BTreeSet;
use std::convert::TryInto;
use std::ops::Deref;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::eyre;

use crate::ledger::storage::traits::{Sha256Hasher, StorageHasher};
use crate::types::address::{Address, InternalAddress};
use crate::types::eth_bridge_pool::{PendingTransfer, TransferToEthereum};
use crate::types::hash::Hash;
use crate::types::keccak::encode::Encode;
use crate::types::keccak::{keccak_hash, KeccakHash};
use crate::types::storage::{DbKeySeg, Key};

/// The main address of the Ethereum bridge pool
pub const BRIDGE_POOL_ADDRESS: Address =
    Address::Internal(InternalAddress::EthBridgePool);
/// Sub-segmnet for getting the contents of the pool
const PENDING_TRANSFERS_SEG: &str = "pending_transfers";
/// Sub-segment for getting the latest signed
const SIGNED_ROOT_SEG: &str = "signed_root";

#[derive(thiserror::Error, Debug)]
#[error(transparent)]
/// Generic error that may be returned by the validity predicate
pub struct Error(#[from] eyre::Error);

/// Get the storage key for the transfers in the pool
pub fn get_pending_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(BRIDGE_POOL_ADDRESS),
            DbKeySeg::StringSeg(PENDING_TRANSFERS_SEG.into()),
        ],
    }
}

/// Get the storage key for the root of the Merkle tree
/// containing the transfers in the pool
pub fn get_signed_root_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(BRIDGE_POOL_ADDRESS),
            DbKeySeg::StringSeg(SIGNED_ROOT_SEG.into()),
        ],
    }
}

/// Check if a key belongs to the bridge pools sub-storage
pub fn is_bridge_pool_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::AddressSeg(addr) if addr == &BRIDGE_POOL_ADDRESS)
}

/// Check if a key belongs to the bridge pool but is not
/// the key for the pending transaction pool. Such keys
/// may not be modified via transactions.
pub fn is_protected_storage(key: &Key) -> bool {
    is_bridge_pool_key(key) && *key != get_pending_key()
}

/// A simple Merkle tree for the Ethereum bridge pool
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct BridgePoolTree {
    /// Root of the tree
    root: KeccakHash,
    /// The underlying storage
    store: BTreeSet<KeccakHash>,
}

impl BridgePoolTree {
    /// Create a new merkle tree for the Ethereum bridge pool
    pub fn new(root: KeccakHash, store: BTreeSet<KeccahkHash>) -> Self {
        Self { root, store }
    }

    /// Parse the key to ensure it is of the correct type.
    ///
    /// If it is, it can be converted to a hash.
    /// Checks if the hash is in the tree.
    pub fn has_key(&self, key: &Key) -> Result<bool, Error> {
        Ok(self.store.contains(&Self::parse_key(key)?))
    }

    /// Update the tree with a new value.
    ///
    /// Returns the new root if successful. Will
    /// return an error if the key is malformed.
    pub fn update(&mut self, key: &Key) -> Result<Hash, Error> {
        let hash = Self::parse_key(key)?;
        _ = self.store.insert(hash);
        self.root = self.compute_root();
        Ok(self.root())
    }

    /// Delete a key from storage and update the root
    pub fn delete(&mut self, key: &Key) -> Result<(), Error> {
        let hash = Self::parse_key(key)?;
        _ = self.store.remove(&hash);
        self.root = self.compute_root();
        Ok(())
    }

    /// Compute the root of the merkle tree
    pub fn compute_root(&self) -> KeccakHash {
        let mut leaves = self.store.iter();
        let mut root = if let Some(hash) = leaves.next() {
            hash.clone()
        } else {
            return Default::default();
        };
        for leaf in leaves {
            root = keccak_hash([root.0, leaf.0].concat());
        }
        root
    }

    /// Return the root as a [`Hash`] type.
    pub fn root(&self) -> Hash {
        self.root.clone().into()
    }

    /// Get a reference to the backing store
    pub fn store(&self) -> &BTreeSet<KeccakHash> {
        &self.store
    }

    /// Create a batched membership proof for the provided keys
    pub fn membership_proof(
        &self,
        keys: &[Key],
        mut values: Vec<PendingTransfer>,
    ) -> Result<BridgePoolProof, Error> {
        if values.len() != keys.len() {
            return eyre!(
                "The number of leaves and leaf hashes must be equal."
            )?;
        }
        values.sort();
        let mut leaves: std::collections::BTreeSet<KeccakHash> =
            Default::default();
        for key in keys {
            leaves.insert(Self::parse_key(key)?);
        }

        let mut proof_hashes = vec![];
        let mut flags = vec![];
        for hash in self.store {
            if leaves.contains(&hash) {
                flags.push(true);
            } else {
                flags.push(false);
                proof_hashes.push(hash);
            }
        }
        Ok(BridgePoolProof {
            proof: proof_hashes,
            leaves: values,
            flags,
        })
    }

    /// Parse a db key to see if it is valid for the
    /// bridge pool.
    ///
    /// It should have one string segment which should
    /// parse into a [Hash]
    fn parse_key(key: &Key) -> Result<KeccakHash, Error> {
        if key.segments.len() == 1 {
            match &key.segments[0] {
                DbKeySeg::StringSeg(str) => str
                    .as_str()
                    .try_into()
                    .ok_or(eyre!("Could not parse key segment as a hash")?),
                _ => {
                    eyre!("Bridge pool keys should be strings, not addresses")?
                }
            }
        } else {
            eyre!(
                "Key for the bridge pool should not have more than one segment"
            )?
        }
    }
}

/// A multi-leaf membership proof
pub struct BridgePoolProof {
    /// The hashes other than the provided leaves
    pub proof: Vec<KeccakHash>,
    /// The leaves; must be sorted
    pub leaves: Vec<PendingTransfer>,
    /// flags to indicate how to combine hashes
    pub flags: Vec<bool>,
}

impl BridgePoolProof {
    /// Verify a membership proof matches the provided root
    pub fn verify(&self, root: KeccakHash) -> bool {
        if self.proof.len() + self.leaves.len() != self.flags.len() {
            return false;
        }
        if self.flags.len() == 0 {
            return true;
        }
        let mut leaf_pos = 0usize;
        let mut proof_pos = 0usize;
        let mut computed;
        if self.flags[0] {
            computed = self.leaves[leaf_pos].keccak256();
            leaf_pos += 1;
        } else {
            computed = self.proof[proof_pos].clone();
            proof_pos += 1;
        }
        for flag in 1..self.flages.len() {
            let mut next_hash;
            if self.flags[flag] {
                next_hash = self.leaves[leaf_pos].keccak256();
                leaf_pos += 1;
            } else {
                next_hash = self.proof[proof_pos].clone();
                proof_pos += 1;
            }
            computed = keccak_hash([computed, next_hash].concat());
        }
        computed == root
    }
}
