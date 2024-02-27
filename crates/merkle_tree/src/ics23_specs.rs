//! A module that contains

use arse_merkle_tree::H256;
use ics23::{HashOp, LeafOp, LengthOp, ProofSpec};
use namada_core::hash::StorageHasher;

/// Get the leaf spec for the base tree. The key is stored after hashing,
/// but the stored value is the subtree's root without hashing.
pub fn base_leaf_spec<H: StorageHasher>() -> LeafOp {
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
pub fn leaf_spec<H: StorageHasher>() -> LeafOp {
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
pub fn ibc_leaf_spec<H: StorageHasher>() -> LeafOp {
    LeafOp {
        hash: H::hash_op().into(),
        prehash_key: HashOp::NoHash.into(),
        prehash_value: HashOp::NoHash.into(),
        length: LengthOp::NoPrefix.into(),
        prefix: H256::zero().as_slice().to_vec(),
    }
}

/// Get the proof specs for ibc
#[allow(dead_code)]
pub fn ibc_proof_specs<H: StorageHasher>() -> Vec<ProofSpec> {
    let spec = arse_merkle_tree::proof_ics23::get_spec(H::hash_op());
    let sub_tree_spec = ProofSpec {
        leaf_spec: Some(ibc_leaf_spec::<H>()),
        ..spec.clone()
    };
    let base_tree_spec = ProofSpec {
        leaf_spec: Some(base_leaf_spec::<H>()),
        ..spec
    };
    vec![sub_tree_spec, base_tree_spec]
}

/// Get the proof specs
#[allow(dead_code)]
pub fn proof_specs<H: StorageHasher>() -> Vec<ProofSpec> {
    let spec = arse_merkle_tree::proof_ics23::get_spec(H::hash_op());
    let sub_tree_spec = ProofSpec {
        leaf_spec: Some(leaf_spec::<H>()),
        ..spec.clone()
    };
    let base_tree_spec = ProofSpec {
        leaf_spec: Some(base_leaf_spec::<H>()),
        ..spec
    };
    vec![sub_tree_spec, base_tree_spec]
}
