//! Tools for accessing the storage subspaces of the Ethereum
//! bridge pool
use std::collections::BTreeSet;
use std::convert::TryInto;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::eyre;

use crate::types::address::{Address, InternalAddress};
use crate::types::eth_bridge_pool::PendingTransfer;
use crate::types::hash::Hash;
use crate::types::keccak::encode::Encode;
use crate::types::keccak::{keccak_hash, KeccakHash};
use crate::types::storage::{DbKeySeg, Key, KeySeg};

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
pub fn get_pending_key(transfer: &PendingTransfer) -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(BRIDGE_POOL_ADDRESS),
            transfer.keccak256().to_db_key(),
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

/// A simple Merkle tree for the Ethereum bridge pool
#[derive(
    Debug, Default, Clone, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct BridgePoolTree {
    /// Root of the tree
    root: KeccakHash,
    /// The underlying storage
    store: BTreeSet<KeccakHash>,
}

impl BridgePoolTree {
    /// Create a new merkle tree for the Ethereum bridge pool
    pub fn new(root: KeccakHash, store: BTreeSet<KeccakHash>) -> Self {
        Self { root, store }
    }

    /// Parse the key to ensure it is of the correct type.
    ///
    /// If it is, it can be converted to a hash.
    /// Checks if the hash is in the tree.
    pub fn contains_key(&self, key: &Key) -> Result<bool, Error> {
        Ok(self.store.contains(&Self::parse_key(key)?))
    }

    /// Update the tree with a new value.
    ///
    /// Returns the new root if successful. Will
    /// return an error if the key is malformed.
    pub fn update_key(&mut self, key: &Key) -> Result<Hash, Error> {
        let hash = Self::parse_key(key)?;
        _ = self.store.insert(hash);
        self.root = self.compute_root();
        Ok(self.root())
    }

    /// Delete a key from storage and update the root
    pub fn delete_key(&mut self, key: &Key) -> Result<(), Error> {
        let hash = Self::parse_key(key)?;
        _ = self.store.remove(&hash);
        self.root = self.compute_root();
        Ok(())
    }

    /// Compute the root of the merkle tree
    pub fn compute_root(&self) -> KeccakHash {
        let mut hashes: Vec<KeccakHash> = self.store.iter().cloned().collect();
        while hashes.len() > 1 {
            let mut next_hashes = vec![];
            let left_leaves = hashes.iter().step_by(2);
            let mut right_leaves = hashes.iter();
            _ = right_leaves.next();
            let mut right_leaves = right_leaves.step_by(2);

            for left in left_leaves {
                let right = right_leaves.next().cloned().unwrap_or_default();
                next_hashes.push(hash_pair(left.clone(), right));
            }
            hashes = next_hashes;
        }

        if hashes.is_empty() {
            Default::default()
        } else {
            hashes.remove(0)
        }
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
    pub fn get_membership_proof(
        &self,
        keys: &[Key],
        mut values: Vec<PendingTransfer>,
    ) -> Result<BridgePoolProof, Error> {
        if values.len() != keys.len() {
            return Err(eyre!(
                "The number of leaves and leaf hashes must be equal."
            )
            .into());
        }
        // sort the values according to their hash values
        values.sort_by_key(|transfer| transfer.keccak256());

        // get the leaf hashes
        let mut leaves: BTreeSet<KeccakHash> = Default::default();
        for (key, value) in keys.iter().zip(values.iter()) {
            let hash = Self::parse_key(key)?;
            if hash != value.keccak256() {
                return Err(eyre!("Hashes of keys did not match hashes of values.").into());
            }
            leaves.insert(hash);
        }

        let mut proof_hashes = vec![];
        let mut flags = vec![];
        let mut hashes: Vec<_> = self
            .store
            .iter()
            .cloned()
            .map(|hash| {
                if leaves.contains(&hash) {
                    Node::OnPath(hash)
                } else {
                    Node::Sibling(hash)
                }
            })
            .collect();

        while hashes.len() > 1 {
            let mut next_hashes = vec![];
            let left_leaves = hashes.iter().step_by(2);
            let mut right_leaves = hashes.iter();
            _ = right_leaves.next();
            let mut right_leaves = right_leaves.step_by(2);

            for left in left_leaves {
                let right = right_leaves.next().cloned().unwrap_or_default();
                match (left, right) {
                    (Node::OnPath(left), Node::OnPath(right)) => {
                        flags.push(true);
                        next_hashes
                            .push(Node::OnPath(hash_pair(left.clone(), right)));
                    }
                    (Node::OnPath(hash), Node::Sibling(sib)) => {
                        flags.push(false);
                        proof_hashes.push(sib.clone());
                        next_hashes
                            .push(Node::OnPath(hash_pair(hash.clone(), sib)));
                    }
                    (Node::Sibling(sib), Node::OnPath(hash)) => {
                        flags.push(false);
                        proof_hashes.push(sib.clone());
                        next_hashes
                            .push(Node::OnPath(hash_pair(hash, sib.clone())));
                    }
                    (Node::Sibling(left), Node::Sibling(right)) => {
                        next_hashes.push(Node::Sibling(hash_pair(
                            left.clone(),
                            right,
                        )));
                    }
                }
            }
            hashes = next_hashes;
        }
        // add the root to the proof
        if flags.is_empty() && proof_hashes.is_empty() && leaves.is_empty() {
            proof_hashes.push(self.root.clone());
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
                DbKeySeg::StringSeg(str) => {
                    str.as_str().try_into().map_err(|_| {
                        eyre!("Could not parse key segment as a hash").into()
                    })
                }
                _ => Err(eyre!(
                    "Bridge pool keys should be strings, not addresses"
                )
                .into()),
            }
        } else {
            Err(eyre!(
                "Key for the bridge pool should not have more than one segment"
            )
            .into())
        }
    }
}

/// Concatenate two keccak hashes and hash the result
#[inline]
fn hash_pair(left: KeccakHash, right: KeccakHash) -> KeccakHash {
    if left.0 < right.0 {
        keccak_hash([left.0, right.0].concat().as_slice())
    } else {
        keccak_hash([right.0, left.0].concat().as_slice())
    }
}

/// Keeps track if a node is on a path from the
/// root of the merkle tree to one of the leaves
/// being included in a multi-proof.
#[derive(Debug, Clone)]
enum Node {
    /// Node is on a path from root to leaf in proof
    OnPath(KeccakHash),
    /// Node is not on a path from root to leaf in proof
    Sibling(KeccakHash),
}

impl Default for Node {
    fn default() -> Self {
        Self::Sibling(Default::default())
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
        if self.proof.len() + self.leaves.len() != self.flags.len() + 1 {
            return false;
        }
        if self.flags.is_empty() {
            return if let Some(leaf) = self.leaves.last() {
                root == leaf.keccak256()
            } else {
                match self.proof.last() {
                    Some(proof_root) => &root == proof_root,
                    None => false,
                }
            };
        }
        let total_hashes = self.flags.len();
        let leaf_len = self.leaves.len();

        let mut hashes = vec![KeccakHash::default(); self.flags.len()];
        let mut hash_pos = 0usize;
        let mut leaf_pos = 0usize;
        let mut proof_pos = 0usize;

        for i in 0..total_hashes {
            let left = if leaf_pos < leaf_len {
                let next = self.leaves[leaf_pos].keccak256();
                leaf_pos += 1;
                next
            } else {
                let next = hashes[hash_pos].clone();
                hash_pos += 1;
                next
            };
            let right = if self.flags[i] {
                if leaf_pos < leaf_len {
                    let next = self.leaves[leaf_pos].keccak256();
                    leaf_pos += 1;
                    next
                } else {
                    let next = hashes[hash_pos].clone();
                    hash_pos += 1;
                    next
                }
            } else {
                let next = self.proof[proof_pos].clone();
                proof_pos += 1;
                next
            };
            hashes[i] = hash_pair(left, right);
        }

        if let Some(computed) = hashes.last() {
            *computed == root
        } else {
            false
        }
    }
}

#[cfg(test)]
mod test_bridge_pool_tree {
    use std::array;

    use itertools::Itertools;
    use proptest::prelude::*;

    use super::*;
    use crate::types::ethereum_events::EthAddress;
    use crate::types::eth_bridge_pool::{GasFee, TransferToEthereum};

    /// An established user address for testing & development
    fn bertha_address() -> Address {
        Address::decode("atest1v4ehgw36xvcyyvejgvenxs34g3zygv3jxqunjd6rxyeyys3sxy6rwvfkx4qnj33hg9qnvse4lsfctw")
            .expect("The token address decoding shouldn't fail")
    }

    /// Test that if tree has a single leaf, its root is the hash
    /// of that leaf
    #[test]
    fn test_update_single_key() {
        let mut tree = BridgePoolTree::default();
        assert_eq!(tree.root().0, [0; 32]);
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([1;20]),
                recipient: EthAddress([2; 20]),
                amount: 1.into(),
                nonce: 42u64.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            }
        };
        let key = Key::from(&transfer);
        let root = KeccakHash::from(tree.update_key(&key).expect("Test failed"));
        assert_eq!(root, transfer.keccak256());
    }

    #[test]
    fn test_two_keys() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..2 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    asset: EthAddress([i;20]),
                    recipient: EthAddress([i+1; 20]),
                    amount: (i as u64).into(),
                    nonce: 42u64.into(),
                },
                gas_fee: GasFee {
                    amount: 0.into(),
                    payer: bertha_address(),
                }
            };
            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.update_key(&key).expect("Test failed");
        }
        let expected: Hash = hash_pair(transfers[0].keccak256(), transfers[1].keccak256()).into();
        assert_eq!(tree.root(), expected);
    }

    /// This is the first number of keys to use dummy leaves
    #[test]
    fn test_three_leaves() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..3 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    asset: EthAddress([i;20]),
                    recipient: EthAddress([i+1; 20]),
                    amount: (i as u64).into(),
                    nonce: 42u64.into(),
                },
                gas_fee: GasFee {
                    amount: 0.into(),
                    payer: bertha_address(),
                }
            };
            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.update_key(&key).expect("Test failed");
        }
        transfers.sort_by_key(|t| t.keccak256());
        let hashes: BTreeSet<KeccakHash> = transfers.iter().map(|t| t.keccak256()).collect();
        assert_eq!(hashes, tree.store);

        let left_hash = hash_pair(transfers[0].keccak256(), transfers[1].keccak256());
        let right_hash = hash_pair(transfers[2].keccak256(), Default::default());
        let expected: Hash = hash_pair(left_hash, right_hash).into();
        assert_eq!(tree.root(), expected);
    }

    /// Test removing all keys
    #[test]
    fn test_delete_all_keys() {
        let mut tree = BridgePoolTree::default();

        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([1;20]),
                recipient: EthAddress([2; 20]),
                amount: 1.into(),
                nonce: 42u64.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            }
        };
        let key = Key::from(&transfer);
        let root = KeccakHash::from(tree.update_key(&key).expect("Test failed"));
        assert_eq!(root, transfer.keccak256());
        tree.delete_key(&key).expect("Test failed");
        assert_eq!(tree.root().0, [0; 32]);
    }

    /// Test deleting a key
    #[test]
    fn test_delete_key() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..3 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    asset: EthAddress([i;20]),
                    recipient: EthAddress([i+1; 20]),
                    amount: (i as u64).into(),
                    nonce: 42u64.into(),
                },
                gas_fee: GasFee {
                    amount: 0.into(),
                    payer: bertha_address(),
                }
            };

            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.update_key(&key).expect("Test failed");
        }
        transfers.sort_by_key(|t| t.keccak256());
        tree.delete_key(&Key::from(&transfers[1]))
            .expect("Test failed");

        let expected: Hash = hash_pair(transfers[0].keccak256(), transfers[2].keccak256()).into();
        assert_eq!(tree.root(), expected);
    }

    /// Test that parse key works correctly
    #[test]
    fn test_parse_key() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([1; 20]),
                recipient: EthAddress([2; 20]),
                amount: 1u64.into(),
                nonce: 42u64.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            }
        };
        let expected = transfer.keccak256();
        let key = Key::from(&transfer);
        assert_eq!(BridgePoolTree::parse_key(&key).expect("Test failed"), expected);
    }

    /// Test that parsing a key with multiple segments fails
    #[test]
    fn test_key_multiple_segments() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([1; 20]),
                recipient: EthAddress([2; 20]),
                amount: 1u64.into(),
                nonce: 42u64.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            }
        };
        let hash = transfer.keccak256().to_string();
        let key = Key{segments: vec![DbKeySeg::AddressSeg(bertha_address()), DbKeySeg::StringSeg(hash)]};
        assert!(BridgePoolTree::parse_key(&key).is_err());
    }

    /// Test that parsing a key that is not a hash fails
    #[test]
    fn test_key_not_hash() {
        let key = Key{segments: vec![DbKeySeg::StringSeg("bloop".into())]};
        assert!(BridgePoolTree::parse_key(&key).is_err());
    }

    /// Test that [`contains_key`] works correctly
    #[test]
    fn test_contains_key() {
        let mut  tree = BridgePoolTree::default();
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([1; 20]),
                recipient: EthAddress([2; 20]),
                amount: 1.into(),
                nonce: 42u64.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            }
        };
        tree.update_key(&Key::from(&transfer)).expect("Test failed");
        assert!(tree.contains_key(&Key::from(&transfer)).expect("Test failed"));
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([1; 20]),
                recipient: EthAddress([0; 20]),
                amount: 1u64.into(),
                nonce: 42u64.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            }
        };
        assert!(!tree.contains_key(&Key::from(&transfer)).expect("Test failed"));
    }

    /// Test that the empty proof works.
    #[test]
    fn test_empty_proof() {
        let tree = BridgePoolTree::default();
        let keys = vec![];
        let values = vec![];
        let proof = tree.get_membership_proof(&keys, values).expect("Test failed");
        assert!(proof.verify(Default::default()));
    }

    /// Test that the proof works for proving the only leaf in the tree
    #[test]
    fn test_single_leaf() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                amount: 0.into(),
                nonce: 0.into()
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address()
            }
        };
        let mut tree = BridgePoolTree::default();
        let key = Key::from(&transfer);
        let _ = tree.update_key(&key).expect("Test failed");
        let proof = tree.get_membership_proof(array::from_ref(&key), vec![transfer]).expect("Test failed");
        assert!(proof.verify(tree.root().into()));
    }

    /// Check proofs for membership of single transfer
    /// in a tree with two leaves.
    #[test]
    fn test_one_leaf_of_two_proof() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..2 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    asset: EthAddress([i;20]),
                    recipient: EthAddress([i+1; 20]),
                    amount: (i as u64).into(),
                    nonce: 42u64.into(),
                },
                gas_fee: GasFee {
                    amount: 0.into(),
                    payer: bertha_address(),
                }
            };

            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.update_key(&key).expect("Test failed");
        }
        let key = Key::from(&transfers[0]);
        let proof = tree.get_membership_proof(
            array::from_ref(&key),
            vec![transfers.remove(0)]
        )
        .expect("Test failed");
        assert!(proof.verify(tree.root().into()));
    }

    /// Test that a multiproof works for leaves who are siblings
    #[test]
    fn test_proof_two_out_of_three_leaves() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..3 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    asset: EthAddress([i;20]),
                    recipient: EthAddress([i+1; 20]),
                    amount: (i as u64).into(),
                    nonce: 42u64.into(),
                },
                gas_fee: GasFee {
                    amount: 0.into(),
                    payer: bertha_address(),
                }
            };

            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.update_key(&key).expect("Test failed");
        }
        transfers.sort_by_key(|t| t.keccak256());
        let keys = vec![Key::from(&transfers[0]), Key::from(&transfers[1])];
        let values = vec![transfers[0].clone(), transfers[1].clone()];
        let proof = tree.get_membership_proof(&keys, values).expect("Test failed");
        assert!(proof.verify(tree.root().into()));
    }

    /// Test that proving an empty subset of leaves always works
    #[test]
    fn test_proof_no_leaves() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..3 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    asset: EthAddress([i;20]),
                    recipient: EthAddress([i+1; 20]),
                    amount: (i as u64).into(),
                    nonce: 42u64.into(),
                },
                gas_fee: GasFee {
                    amount: 0.into(),
                    payer: bertha_address(),
                }
            };
            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.update_key(&key).expect("Test failed");
        }
        let keys = vec![];
        let values = vec![];
        let proof = tree.get_membership_proof(&keys, values).expect("Test failed");
        assert!(proof.verify(tree.root().into()))
    }

    /// Test a proof for all the leaves
    #[test]
    fn test_proof_all_leaves() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..2 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    asset: EthAddress([i;20]),
                    recipient: EthAddress([i+1; 20]),
                    amount: (i as u64).into(),
                    nonce: 42u64.into(),
                },
                gas_fee: GasFee {
                    amount: 0.into(),
                    payer: bertha_address(),
                }
            };
            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.update_key(&key).expect("Test failed");
        }
        transfers.sort_by_key(|t| t.keccak256());
        let keys: Vec<_> = transfers.iter().map(Key::from).collect();
        let proof = tree.get_membership_proof(&keys, transfers).expect("Test failed");
        assert!(proof.verify(tree.root().into()));
    }

    /// Test a proof for all the leaves when the number of leaves is odd
    #[test]
    fn test_proof_all_leaves_odd() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..3 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    asset: EthAddress([i;20]),
                    recipient: EthAddress([i+1; 20]),
                    amount: (i as u64).into(),
                    nonce: 42u64.into(),
                },
                gas_fee: GasFee {
                    amount: 0.into(),
                    payer: bertha_address(),
                }
            };
            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.update_key(&key).expect("Test failed");
        }
        transfers.sort_by_key(|t| t.keccak256());
        let keys: Vec<_> = transfers.iter().map(Key::from).collect();
        let proof = tree.get_membership_proof(&keys, transfers).expect("Test failed");
        assert!(proof.verify(tree.root().into()));
    }

    /// Test proofs of large trees
    #[test]
    fn test_large_proof() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..5 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    asset: EthAddress([i;20]),
                    recipient: EthAddress([i+1; 20]),
                    amount: (i as u64).into(),
                    nonce: 42u64.into(),
                },
                gas_fee: GasFee {
                    amount: 0.into(),
                    payer: bertha_address(),
                }
            };
            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.update_key(&key).expect("Test failed");
        }
        transfers.sort_by_key(|t| t.keccak256());
        let keys: Vec<_> = transfers
            .iter()
            .step_by(2)
            .map(Key::from)
            .collect();
        let values: Vec<_> = transfers
            .iter()
            .step_by(2)
            .cloned()
            .collect();
        let proof = tree.get_membership_proof(&keys, values).expect("Test failed");
        assert!(proof.verify(tree.root().into()));
    }

    /// Create a random set of transfers.
    fn random_transfers(number: usize) -> impl Strategy<Value=Vec<PendingTransfer>> {
        prop::collection::vec(
            (
                prop::array::uniform20(0u8..),
                prop::num::u64::ANY,
            ),
            0..=number,
        )
        .prop_flat_map( | addrs |
            Just(
                addrs.into_iter().map(| (addr, nonce)|
                    PendingTransfer {
                        transfer: TransferToEthereum {
                            asset: EthAddress(addr),
                            recipient: EthAddress(addr),
                            amount: Default::default(),
                            nonce: nonce.into()
                        },
                        gas_fee: GasFee {
                            amount: Default::default(),
                            payer: bertha_address()
                        }
                    },
                )
                .dedup()
                .collect::<Vec<PendingTransfer>>()
            )
        )
    }

    prop_compose! {
        /// Creates a random set of transfers and
        /// then returns them along with a chosen subset.
        fn arb_transfers_and_subset()
        (transfers in random_transfers(50))
        (
            transfers in Just(transfers.clone()),
            to_prove in proptest::sample::subsequence(transfers.clone(), 0..=transfers.len()),
        )
        -> (Vec<PendingTransfer>, Vec<PendingTransfer>) {
            (transfers, to_prove)
        }
    }

    proptest!{
        /// Given a random tree and a subset of leaves,
        /// verify that the constructed multi-proof correctly
        /// verifies.
        #[test]
        fn test_verify_proof((transfers, mut to_prove) in arb_transfers_and_subset()) {
            let mut tree = BridgePoolTree::default();
            for transfer in &transfers {
                let key = Key::from(transfer);
                let _ = tree.update_key(&key).expect("Test failed");
            }

            to_prove.sort_by_key(|t| t.keccak256());
            let mut keys = vec![];
            let mut values = vec![];
            for transfer in to_prove.into_iter() {
                keys.push(Key::from(&transfer));
                values.push(transfer);
            }
            let proof = tree.get_membership_proof(&keys, values).expect("Test failed");
            assert!(proof.verify(tree.root().into()));
        }
    }
}