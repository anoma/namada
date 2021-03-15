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
    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct TxDataIn(pub Vec<u8>);

    /// The storage write log of storage updates performed by the
    /// transaction for the account associated with the VP
    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct WriteLogIn(pub Vec<StorageUpdate>);

    pub type TxIn = TxDataIn;
    pub type VpIn = (TxDataIn, WriteLogIn);

    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct StorageReadIn {
        pub addr: String,
        pub key: String,
    }

    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct StorageReadOut {
        pub data: Option<Vec<u8>>,
    }

    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct StorageHasKeyIn {
        pub addr: String,
        pub key: String,
    }
    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct StorageHasKeyOut(pub bool);

    /// The storage update is stored in the host, so there is no output
    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct StorageUpdateIn(pub StorageUpdate);

    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct StorageReadSelfIn {
        key: String,
    }

    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct StorageReadSelfOut {
        pub data: Option<Vec<u8>>,
    }

    /// Check if a VP at the given address approved the transaction
    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct OtherApprovedIn {
        addr: String,
    }

    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct OtherApprovedOut(pub bool);
}
