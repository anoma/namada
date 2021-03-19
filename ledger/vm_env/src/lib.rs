//! This crate contains code that is shared between the VM host (the ledger) and
//! the guest (wasm code).

use borsh::{BorshDeserialize, BorshSerialize};

/// Storage modifications
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum StorageUpdate {
    Update { key: String, value: String },
    Delete { key: String },
}

/// Memory types can be passed between the host and guest via wasm linear
/// memory.
///
/// These are either:
/// 1. Module call types
///    The module call inputs are passed host-to-guest.
///
/// 2. Execution environment types
///    The environment inputs are passed guest-to-host and outputs back from
///    host-to-guest.
pub mod memory {
    use super::*;

    /// The data attached to the transaction that initiated the wasm call
    /// (tx or VP)
    pub type TxData = Vec<u8>;

    /// The storage write log of storage updates performed by the
    /// transaction for the account associated with the VP
    pub type WriteLog = Vec<StorageUpdate>;

    /// Input for transaction wasm module call
    pub type TxInput = TxData;

    /// Input for validity predicate wasm module call
    pub type VpInput<'a> = (String, &'a TxData, &'a WriteLog);

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
    pub struct StorageUpdateInput(pub StorageUpdate);

    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct StorageReadSelfInput {
        key: String,
    }

    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct StorageReadSelfOutput {
        pub data: Option<Vec<u8>>,
    }

    /// Check if a VP at the given address approved the transaction
    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct OtherApprovedInput {
        addr: String,
    }

    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct OtherApprovedOutput(pub bool);
}
