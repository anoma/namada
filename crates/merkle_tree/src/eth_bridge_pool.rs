//! Ethereum bridge pool merkle tree

use std::collections::{BTreeMap, BTreeSet};

use eyre::eyre;
use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::eth_abi::{Encode, Token};
use namada_core::eth_bridge_pool::PendingTransfer;
use namada_core::hash::Hash;
use namada_core::keccak::{keccak_hash, KeccakHash};
use namada_core::storage;
use namada_core::storage::{BlockHeight, DbKeySeg};

#[derive(thiserror::Error, Debug)]
#[error(transparent)]
/// Generic error that may be returned by the validity predicate
pub struct Error(#[from] eyre::Error);

/// Prefix to be used in Bridge pool tree root computations.
/// This value corresponds to leaf nodes.
const POOL_ROOT_PREFIX_LEAF: u8 = 0x00;

/// Prefix to be used in Bridge pool tree root computations.
/// This value corresponds to non-leaf nodes.
const POOL_ROOT_PREFIX_NON_LEAF: u8 = 0xff;

/// A simple Merkle tree for the Ethereum bridge pool
///
/// Note that an empty tree has root [0u8; 20] by definition.
#[derive(
    Debug, Default, Clone, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct BridgePoolTree {
    /// Root of the tree
    root: KeccakHash,
    /// The underlying storage, containing hashes of [`PendingTransfer`]s.
    leaves: BTreeMap<KeccakHash, BlockHeight>,
}

impl BridgePoolTree {
    /// Create a new merkle tree for the Ethereum bridge pool
    pub fn new(
        root: KeccakHash,
        store: BTreeMap<KeccakHash, BlockHeight>,
    ) -> Self {
        Self {
            root,
            leaves: store,
        }
    }

    /// Parse the key to ensure it is of the correct type.
    ///
    /// If it is, it can be converted to a hash.
    /// Checks if the hash is in the tree.
    pub fn contains_key(&self, key: &storage::Key) -> Result<bool, Error> {
        Ok(self.leaves.contains_key(&Self::parse_key(key)?))
    }

    /// Get the height at which the key was inserted
    ///
    /// Returns the height if successful. Will
    /// return an error if the key is malformed.
    pub fn get(&self, key: &storage::Key) -> Result<BlockHeight, Error> {
        let hash = Self::parse_key(key)?;
        self.leaves.get(&hash).cloned().ok_or_else(|| {
            eyre!("Key not present in Bridge Pool merkle tree.").into()
        })
    }

    /// Update the tree with a new value.
    ///
    /// Returns the new root if successful. Will
    /// return an error if the key is malformed.
    pub fn insert_key(
        &mut self,
        key: &storage::Key,
        value: BlockHeight,
    ) -> Result<Hash, Error> {
        let hash = Self::parse_key(key)?;
        _ = self.leaves.insert(hash, value);
        self.root = self.compute_root();
        Ok(self.root().into())
    }

    /// Delete a key from storage and update the root
    pub fn delete_key(&mut self, key: &storage::Key) -> Result<(), Error> {
        let hash = Self::parse_key(key)?;
        _ = self.leaves.remove(&hash);
        self.root = self.compute_root();
        Ok(())
    }

    /// Compute the root of the merkle tree
    fn compute_root(&self) -> KeccakHash {
        let mut hashes: Vec<KeccakHash> = self.leaves.keys().cloned().collect();
        let mut prefix = POOL_ROOT_PREFIX_LEAF;
        while hashes.len() > 1 {
            let mut next_hashes = vec![];
            for pair in hashes.chunks(2) {
                let left = pair[0].clone();
                let right = pair.get(1).cloned().unwrap_or_default();
                next_hashes.push(hash_pair(left, right, prefix));
            }
            hashes = next_hashes;
            prefix = POOL_ROOT_PREFIX_NON_LEAF;
        }

        if hashes.is_empty() {
            Default::default()
        } else {
            hashes.remove(0)
        }
    }

    /// Return the root as a [`struct@Hash`] type.
    pub fn root(&self) -> KeccakHash {
        self.root.clone()
    }

    /// Get a reference to the backing store
    pub fn store(&self) -> &BTreeMap<KeccakHash, BlockHeight> {
        &self.leaves
    }

    /// Create a batched membership proof for the provided keys
    pub fn get_membership_proof(
        &self,
        mut values: Vec<PendingTransfer>,
    ) -> Result<BridgePoolProof, Error> {
        // sort the values according to their hash values
        values.sort_by_key(|transfer| transfer.keccak256());

        // get the leaf hashes
        let leaves: BTreeSet<KeccakHash> =
            values.iter().map(|v| v.keccak256()).collect();
        if !leaves.iter().all(|h| self.leaves.contains_key(h)) {
            return Err(eyre!(
                "Cannot generate proof for values that aren't in the tree"
            )
            .into());
        }
        let mut proof_hashes = vec![];
        let mut flags = vec![];
        let mut hashes: Vec<_> = self
            .leaves
            .keys()
            .cloned()
            .map(|hash| {
                if leaves.contains(&hash) {
                    Node::OnPath(hash)
                } else {
                    Node::OffPath(hash)
                }
            })
            .collect();

        let mut prefix = POOL_ROOT_PREFIX_LEAF;

        while hashes.len() > 1 {
            let mut next_hashes = vec![];

            for pair in hashes.chunks(2) {
                let left = pair[0].clone();
                let right = pair.get(1).cloned().unwrap_or_default();
                match (left, right) {
                    (Node::OnPath(left), Node::OnPath(right)) => {
                        flags.push(true);
                        next_hashes.push(Node::OnPath(hash_pair(
                            left.clone(),
                            right,
                            prefix,
                        )));
                    }
                    (Node::OnPath(hash), Node::OffPath(sib)) => {
                        flags.push(false);
                        proof_hashes.push(sib.clone());
                        next_hashes.push(Node::OnPath(hash_pair(
                            hash.clone(),
                            sib,
                            prefix,
                        )));
                    }
                    (Node::OffPath(sib), Node::OnPath(hash)) => {
                        flags.push(false);
                        proof_hashes.push(sib.clone());
                        next_hashes.push(Node::OnPath(hash_pair(
                            hash,
                            sib.clone(),
                            prefix,
                        )));
                    }
                    (Node::OffPath(left), Node::OffPath(right)) => {
                        next_hashes.push(Node::OffPath(hash_pair(
                            left.clone(),
                            right,
                            prefix,
                        )));
                    }
                }
            }
            hashes = next_hashes;
            prefix = POOL_ROOT_PREFIX_NON_LEAF;
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
    /// parse into a [`struct@Hash`].
    pub fn parse_key(key: &storage::Key) -> Result<KeccakHash, Error> {
        if key.segments.len() == 1 {
            match &key.segments[0] {
                DbKeySeg::StringSeg(str) => {
                    str.as_str().try_into().map_err(|_| {
                        eyre!("Could not parse key segment as a hash").into()
                    })
                }
                _ => Err(eyre!("Bridge pool keys should be strings.").into()),
            }
        } else {
            Err(eyre!(
                "Key for the bridge pool should have exactly one segment."
            )
            .into())
        }
    }
}

/// Concatenate a byte prefix and two keccak hashes,
/// then compute the keccak hash of the resulting
/// byte array.
#[inline]
fn hash_pair(left: KeccakHash, right: KeccakHash, prefix: u8) -> KeccakHash {
    let mut buf = [0u8; 32 + 32 + 1];
    buf[0] = prefix;
    if left.0 < right.0 {
        buf[1..33].copy_from_slice(&left.0);
        buf[33..].copy_from_slice(&right.0);
    } else {
        buf[1..33].copy_from_slice(&right.0);
        buf[33..].copy_from_slice(&left.0);
    }
    keccak_hash(buf)
}

/// Keeps track if a node is on a path from the
/// root of the merkle tree to one of the leaves
/// being included in a multi-proof.
#[derive(Debug, Clone)]
enum Node {
    /// Node is on a path from root to leaf in proof
    OnPath(KeccakHash),
    /// Node is not on a path from root to leaf in proof
    OffPath(KeccakHash),
}

impl Default for Node {
    fn default() -> Self {
        Self::OffPath(Default::default())
    }
}

/// A multi-leaf membership proof
pub struct BridgePoolProof {
    /// The hashes other than the provided leaves
    pub proof: Vec<KeccakHash>,
    /// The leaves; must be sorted
    pub leaves: Vec<PendingTransfer>,
    /// Flags are used to indicate which consecutive
    /// pairs of leaves in `leaves` are siblings.
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
            let (left, prefix) = if leaf_pos < leaf_len {
                let next = self.leaves[leaf_pos].keccak256();
                leaf_pos += 1;
                (next, POOL_ROOT_PREFIX_LEAF)
            } else {
                let next = hashes[hash_pos].clone();
                hash_pos += 1;
                (next, POOL_ROOT_PREFIX_NON_LEAF)
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
            hashes[i] = hash_pair(left, right, prefix);
        }

        if let Some(computed) = hashes.last() {
            *computed == root
        } else {
            false
        }
    }
}

impl Encode<3> for BridgePoolProof {
    fn tokenize(&self) -> [Token; 3] {
        let BridgePoolProof {
            proof,
            leaves,
            flags,
        } = self;
        let proof = Token::Array(
            proof
                .iter()
                .map(|hash| Token::FixedBytes(hash.0.to_vec()))
                .collect(),
        );
        let transfers = Token::Array(
            leaves
                .iter()
                .map(|t| Token::FixedArray(t.tokenize().to_vec()))
                .collect(),
        );
        let flags =
            Token::Array(flags.iter().map(|flag| Token::Bool(*flag)).collect());
        [proof, transfers, flags]
    }
}

#[cfg(test)]
mod test_bridge_pool_tree {

    use assert_matches::assert_matches;
    use itertools::Itertools;
    use namada_core::address::testing::nam;
    use namada_core::address::Address;
    use namada_core::eth_bridge_pool::{
        GasFee, TransferToEthereum, TransferToEthereumKind,
    };
    use namada_core::ethereum_events::EthAddress;
    use namada_core::storage::Key;
    use proptest::prelude::*;

    use super::*;

    /// An established user address for testing & development
    fn bertha_address() -> Address {
        Address::decode("tnam1qyctxtpnkhwaygye0sftkq28zedf774xc5a2m7st")
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
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([1; 20]),
                sender: bertha_address(),
                recipient: EthAddress([2; 20]),
                amount: 1.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };
        let key = Key::from(&transfer);
        let root = KeccakHash::from(
            tree.insert_key(&key, BlockHeight(1)).expect("Test failed"),
        );
        assert_eq!(root, transfer.keccak256());
        let height = tree.get(&key).expect("Test failed");
        assert_eq!(BlockHeight(1), height);
    }

    #[test]
    fn test_two_keys() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..2 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    kind: TransferToEthereumKind::Erc20,
                    asset: EthAddress([i; 20]),
                    sender: bertha_address(),
                    recipient: EthAddress([i + 1; 20]),
                    amount: (i as u64).into(),
                },
                gas_fee: GasFee {
                    token: nam(),
                    amount: 0.into(),
                    payer: bertha_address(),
                },
            };
            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.insert_key(&key, BlockHeight(1)).expect("Test failed");
        }
        let expected = hash_pair(
            transfers[0].keccak256(),
            transfers[1].keccak256(),
            POOL_ROOT_PREFIX_LEAF,
        );
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
                    kind: TransferToEthereumKind::Erc20,
                    asset: EthAddress([i; 20]),
                    sender: bertha_address(),
                    recipient: EthAddress([i + 1; 20]),
                    amount: (i as u64).into(),
                },
                gas_fee: GasFee {
                    token: nam(),
                    amount: 0.into(),
                    payer: bertha_address(),
                },
            };
            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.insert_key(&key, BlockHeight(1)).expect("Test failed");
        }
        transfers.sort_by_key(|t| t.keccak256());
        let hashes: BTreeSet<KeccakHash> =
            transfers.iter().map(|t| t.keccak256()).collect();
        assert_eq!(
            hashes,
            tree.leaves.keys().cloned().collect::<BTreeSet<_>>()
        );

        let left_hash = hash_pair(
            transfers[0].keccak256(),
            transfers[1].keccak256(),
            POOL_ROOT_PREFIX_LEAF,
        );
        let right_hash = hash_pair(
            transfers[2].keccak256(),
            Default::default(),
            POOL_ROOT_PREFIX_LEAF,
        );
        let expected =
            hash_pair(left_hash, right_hash, POOL_ROOT_PREFIX_NON_LEAF);
        assert_eq!(tree.root(), expected);
    }

    /// Test removing all keys
    #[test]
    fn test_delete_all_keys() {
        let mut tree = BridgePoolTree::default();

        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([1; 20]),
                sender: bertha_address(),
                recipient: EthAddress([2; 20]),
                amount: 1.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };
        let key = Key::from(&transfer);
        let root = KeccakHash::from(
            tree.insert_key(&key, BlockHeight(1)).expect("Test failed"),
        );
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
                    kind: TransferToEthereumKind::Erc20,
                    asset: EthAddress([i; 20]),
                    sender: bertha_address(),
                    recipient: EthAddress([i + 1; 20]),
                    amount: (i as u64).into(),
                },
                gas_fee: GasFee {
                    token: nam(),
                    amount: 0.into(),
                    payer: bertha_address(),
                },
            };

            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.insert_key(&key, BlockHeight(1)).expect("Test failed");
        }
        transfers.sort_by_key(|t| t.keccak256());
        let deleted_key = Key::from(&transfers[1]);
        tree.delete_key(&deleted_key).expect("Test failed");

        let expected = hash_pair(
            transfers[0].keccak256(),
            transfers[2].keccak256(),
            POOL_ROOT_PREFIX_LEAF,
        );
        assert_eq!(tree.root(), expected);
        assert_matches!(tree.get(&deleted_key), Err(_));
    }

    /// Test that parse key works correctly
    #[test]
    fn test_parse_key() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([1; 20]),
                sender: bertha_address(),
                recipient: EthAddress([2; 20]),
                amount: 1u64.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };
        let expected = transfer.keccak256();
        let key = Key::from(&transfer);
        assert_eq!(
            BridgePoolTree::parse_key(&key).expect("Test failed"),
            expected
        );
    }

    /// Test that parsing a key with multiple segments fails
    #[test]
    fn test_key_multiple_segments() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([1; 20]),
                sender: bertha_address(),
                recipient: EthAddress([2; 20]),
                amount: 1u64.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };
        let hash = transfer.keccak256().to_string();
        let key = Key {
            segments: vec![
                DbKeySeg::AddressSeg(bertha_address()),
                DbKeySeg::StringSeg(hash),
            ],
        };
        assert!(BridgePoolTree::parse_key(&key).is_err());
    }

    /// Test that parsing a key that is not a hash fails
    #[test]
    fn test_key_not_hash() {
        let key = Key {
            segments: vec![DbKeySeg::StringSeg("bloop".into())],
        };
        assert!(BridgePoolTree::parse_key(&key).is_err());
    }

    /// Test that [`contains_key`] works correctly
    #[test]
    fn test_contains_key() {
        let mut tree = BridgePoolTree::default();
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([1; 20]),
                sender: bertha_address(),
                recipient: EthAddress([2; 20]),
                amount: 1.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };
        tree.insert_key(&Key::from(&transfer), BlockHeight(1))
            .expect("Test failed");
        assert!(
            tree.contains_key(&Key::from(&transfer))
                .expect("Test failed")
        );
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([1; 20]),
                sender: bertha_address(),
                recipient: EthAddress([0; 20]),
                amount: 1u64.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };
        assert!(
            !tree
                .contains_key(&Key::from(&transfer))
                .expect("Test failed")
        );
    }

    /// Test that the empty proof works.
    #[test]
    fn test_empty_proof() {
        let tree = BridgePoolTree::default();
        let values = vec![];
        let proof = tree.get_membership_proof(values).expect("Test failed");
        assert!(proof.verify(Default::default()));
    }

    /// Test that the proof works for proving the only leaf in the tree
    #[test]
    fn test_single_leaf() {
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                asset: EthAddress([0; 20]),
                sender: bertha_address(),
                recipient: EthAddress([0; 20]),
                amount: 0.into(),
            },
            gas_fee: GasFee {
                token: nam(),
                amount: 0.into(),
                payer: bertha_address(),
            },
        };
        let mut tree = BridgePoolTree::default();
        let key = Key::from(&transfer);
        let _ = tree.insert_key(&key, BlockHeight(1)).expect("Test failed");
        let proof = tree
            .get_membership_proof(vec![transfer])
            .expect("Test failed");
        assert!(proof.verify(tree.root()));
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
                    kind: TransferToEthereumKind::Erc20,
                    asset: EthAddress([i; 20]),
                    sender: bertha_address(),
                    recipient: EthAddress([i + 1; 20]),
                    amount: (i as u64).into(),
                },
                gas_fee: GasFee {
                    token: nam(),
                    amount: 0.into(),
                    payer: bertha_address(),
                },
            };

            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.insert_key(&key, BlockHeight(1)).expect("Test failed");
        }
        let proof = tree
            .get_membership_proof(vec![transfers.remove(0)])
            .expect("Test failed");
        assert!(proof.verify(tree.root()));
    }

    /// Test that a multiproof works for leaves who are siblings
    #[test]
    fn test_proof_two_out_of_three_leaves() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..3 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    kind: TransferToEthereumKind::Erc20,
                    asset: EthAddress([i; 20]),
                    sender: bertha_address(),
                    recipient: EthAddress([i + 1; 20]),
                    amount: (i as u64).into(),
                },
                gas_fee: GasFee {
                    token: nam(),
                    amount: 0.into(),
                    payer: bertha_address(),
                },
            };

            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.insert_key(&key, BlockHeight(1)).expect("Test failed");
        }
        transfers.sort_by_key(|t| t.keccak256());
        let values = vec![transfers[0].clone(), transfers[1].clone()];
        let proof = tree.get_membership_proof(values).expect("Test failed");
        assert!(proof.verify(tree.root()));
    }

    /// Test that proving an empty subset of leaves always works
    #[test]
    fn test_proof_no_leaves() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..3 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    kind: TransferToEthereumKind::Erc20,
                    asset: EthAddress([i; 20]),
                    sender: bertha_address(),
                    recipient: EthAddress([i + 1; 20]),
                    amount: (i as u64).into(),
                },
                gas_fee: GasFee {
                    token: nam(),
                    amount: 0.into(),
                    payer: bertha_address(),
                },
            };
            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.insert_key(&key, BlockHeight(1)).expect("Test failed");
        }
        let values = vec![];
        let proof = tree.get_membership_proof(values).expect("Test failed");
        assert!(proof.verify(tree.root()))
    }

    /// Test a proof for all the leaves
    #[test]
    fn test_proof_all_leaves() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..2 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    kind: TransferToEthereumKind::Erc20,
                    asset: EthAddress([i; 20]),
                    sender: bertha_address(),
                    recipient: EthAddress([i + 1; 20]),
                    amount: (i as u64).into(),
                },
                gas_fee: GasFee {
                    token: nam(),
                    amount: 0.into(),
                    payer: bertha_address(),
                },
            };
            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.insert_key(&key, BlockHeight(1)).expect("Test failed");
        }
        transfers.sort_by_key(|t| t.keccak256());
        let proof = tree.get_membership_proof(transfers).expect("Test failed");
        assert!(proof.verify(tree.root()));
    }

    /// Test a proof for all the leaves when the number of leaves is odd
    #[test]
    fn test_proof_all_leaves_odd() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..3 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    kind: TransferToEthereumKind::Erc20,
                    asset: EthAddress([i; 20]),
                    sender: bertha_address(),
                    recipient: EthAddress([i + 1; 20]),
                    amount: (i as u64).into(),
                },
                gas_fee: GasFee {
                    token: nam(),
                    amount: 0.into(),
                    payer: bertha_address(),
                },
            };
            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.insert_key(&key, BlockHeight(1)).expect("Test failed");
        }
        transfers.sort_by_key(|t| t.keccak256());
        let proof = tree.get_membership_proof(transfers).expect("Test failed");
        assert!(proof.verify(tree.root()));
    }

    /// Test proofs of large trees
    #[test]
    fn test_large_proof() {
        let mut tree = BridgePoolTree::default();
        let mut transfers = vec![];
        for i in 0..5 {
            let transfer = PendingTransfer {
                transfer: TransferToEthereum {
                    kind: TransferToEthereumKind::Erc20,
                    asset: EthAddress([i; 20]),
                    sender: bertha_address(),
                    recipient: EthAddress([i + 1; 20]),
                    amount: (i as u64).into(),
                },
                gas_fee: GasFee {
                    token: nam(),
                    amount: 0.into(),
                    payer: bertha_address(),
                },
            };
            let key = Key::from(&transfer);
            transfers.push(transfer);
            let _ = tree.insert_key(&key, BlockHeight(1)).expect("Test failed");
        }
        transfers.sort_by_key(|t| t.keccak256());
        let values: Vec<_> = transfers.iter().step_by(2).cloned().collect();
        let proof = tree.get_membership_proof(values).expect("Test failed");
        assert!(proof.verify(tree.root()));
    }

    /// Create a random set of transfers.
    fn random_transfers(
        number: usize,
    ) -> impl Strategy<Value = Vec<PendingTransfer>> {
        prop::collection::vec(prop::array::uniform20(0u8..), 0..=number)
            .prop_flat_map(|addrs| {
                Just(
                    addrs
                        .into_iter()
                        .map(|addr| PendingTransfer {
                            transfer: TransferToEthereum {
                                kind: TransferToEthereumKind::Erc20,
                                asset: EthAddress(addr),
                                sender: bertha_address(),
                                recipient: EthAddress(addr),
                                amount: Default::default(),
                            },
                            gas_fee: GasFee {
                                token: nam(),
                                amount: Default::default(),
                                payer: bertha_address(),
                            },
                        })
                        .dedup()
                        .collect::<Vec<PendingTransfer>>(),
                )
            })
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

    proptest! {
        /// Given a random tree and a subset of leaves,
        /// verify that the constructed multi-proof correctly
        /// verifies.
        #[test]
        fn test_verify_proof((transfers, mut to_prove) in arb_transfers_and_subset()) {
            let mut tree = BridgePoolTree::default();
            for transfer in &transfers {
                let key = Key::from(transfer);
                let _ = tree.insert_key(&key, BlockHeight(1)).expect("Test failed");
            }

            to_prove.sort_by_key(|t| t.keccak256());
            let proof = tree.get_membership_proof(to_prove).expect("Test failed");
            assert!(proof.verify(tree.root()));
        }
    }
}
