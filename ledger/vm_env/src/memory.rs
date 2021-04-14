//! Memory types can be passed between the host and guest via wasm linear
//! memory.
//!
//! These are either:
//! 1. Module call types
//!    The module call inputs are passed host-to-guest.
//!
//! 2. Execution environment types
//!    The environment inputs are passed guest-to-host and outputs back from
//!    host-to-guest.

use borsh::{BorshDeserialize, BorshSerialize};
use std::marker::PhantomData;

/// The data type that can be attached to the operation that initiated the
/// wasm call (tx, VP, matchmaker, filter)
pub type Data = Vec<u8>;

/// The storage changed keys from the write log of storage updates performed
/// by the transaction for the account associated with the VP
pub type KeysChanged = Vec<String>;

/// Input for transaction wasm module call
pub type TxInput = Data;

/// Input for validity predicate wasm module call
pub type VpInput<'a> = (String, &'a Data, &'a KeysChanged);

/// Input for matchmaker wasm module call
pub type MatchmakerInput = Data;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct KeyVal {
    pub key: String,
    pub val: Vec<u8>,
}

pub struct KeyValIterator<T>(pub u64, pub PhantomData<T>);
pub struct PreKeyValIterator<T>(pub u64, pub PhantomData<T>);
pub struct PostKeyValIterator<T>(pub u64, pub PhantomData<T>);

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct StorageReadInput {
    pub addr: String,
    pub key: String,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct StorageReadOutput {
    pub data: Option<Vec<u8>>,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct StorageHasKeyInput {
    pub addr: String,
    pub key: String,
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct StorageHasKeyOutput(pub bool);

/// The storage update is stored in the host, so there is no output
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct StorageWriteInput {
    pub key: String,
    pub val: Vec<u8>,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct StorageReadSelfInput {
    pub key: String,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct StorageReadSelfOutput {
    pub data: Option<Vec<u8>>,
}

/// Check if a VP at the given address approved the transaction
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct OtherApprovedInput {
    pub addr: String,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct OtherApprovedOutput(pub bool);
