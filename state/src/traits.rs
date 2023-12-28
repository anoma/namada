//! Traits needed to provide a uniform interface over
//! all the different Merkle trees used for storage
use std::convert::TryInto;
use std::fmt;

use arse_merkle_tree::traits::{Hasher, Value};
use arse_merkle_tree::H256;
use ics23::commitment_proof::Proof as Ics23Proof;
use ics23::{CommitmentProof, ExistenceProof};
use namada_core::borsh::{BorshDeserialize, BorshSerializeExt};
use namada_core::types::hash::StorageHasher;
use namada_core::types::storage::Key;
use sha2::{Digest, Sha256};
use tiny_keccak::Hasher as KHasher;

use super::ics23_specs;
use super::merkle_tree::{Amt, Error, MerkleRoot, Smt};
use crate::ledger::eth_bridge::storage::bridge_pool::BridgePoolTree;
use crate::ledger::storage::merkle_tree::StorageBytes;
use crate::types::eth_bridge_pool::PendingTransfer;
use crate::types::hash::Hash;
use crate::types::storage::{
    BlockHeight, Key, MembershipProof, StringKey, TreeBytes, IBC_KEY_LIMIT,
};
