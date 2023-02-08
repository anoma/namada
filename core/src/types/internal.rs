//! Shared internal types between the host env and guest (wasm).

use borsh::{BorshDeserialize, BorshSerialize};

/// A result of a wasm call to host functions that may fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostEnvResult {
    /// A success
    Success = 1,
    /// A non-fatal failure does **not** interrupt WASM execution
    Fail = -1,
}

/// Key-value pair represents data from account's subspace.
/// It is used for prefix iterator's WASM host_env functions.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct KeyVal {
    /// The storage key
    pub key: String,
    /// The value as arbitrary bytes
    pub val: Vec<u8>,
}

impl HostEnvResult {
    /// Convert result to `i64`, which can be passed to wasm
    pub fn to_i64(self) -> i64 {
        self as _
    }

    /// Check if the given result as `i64` is a success
    pub fn is_success(int: i64) -> bool {
        int == Self::Success.to_i64()
    }

    /// Check if the given result as `i64` is a non-fatal failure
    pub fn is_fail(int: i64) -> bool {
        int == Self::Fail.to_i64()
    }
}

impl From<bool> for HostEnvResult {
    fn from(success: bool) -> Self {
        if success {
            Self::Success
        } else {
            Self::Fail
        }
    }
}

#[cfg(feature = "ferveo-tpke")]
mod tx_queue {
    use borsh::{BorshDeserialize, BorshSerialize};

    /// A wrapper for `crate::types::transaction::WrapperTx` to conditionally
    /// add `has_valid_pow` flag for only used in testnets.
    #[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
    pub struct WrapperTxInQueue {
        /// Wrapper tx
        pub tx: crate::types::transaction::WrapperTx,
        /// The available gas remaining for the inner tx (for gas accounting)
        pub gas: u64,
        #[cfg(not(feature = "mainnet"))]
        /// A PoW solution can be used to allow zero-fee testnet
        /// transactions.
        /// This is true when the wrapper of this tx contains a valid
        /// `testnet_pow::Solution`
        pub has_valid_pow: bool,
    }

    #[derive(Default, Debug, Clone, BorshDeserialize, BorshSerialize)]
    /// Wrapper txs to be decrypted in the next block proposal
    pub struct TxQueue(std::collections::VecDeque<WrapperTxInQueue>);

    impl TxQueue {
        /// Add a new wrapper at the back of the queue
        pub fn push(&mut self, wrapper: WrapperTxInQueue) {
            self.0.push_back(wrapper);
        }

        /// Remove the wrapper at the head of the queue
        pub fn pop(&mut self) -> Option<WrapperTxInQueue> {
            self.0.pop_front()
        }

        /// Get an iterator over the queue
        pub fn iter(
            &self,
        ) -> impl std::iter::Iterator<Item = &WrapperTxInQueue> {
            self.0.iter()
        }

        /// Check if there are any txs in the queue
        #[allow(dead_code)]
        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }

        /// Get reference to the element at the given index.
        /// Returns [`None`] if index exceeds the queue lenght.
        pub fn get(&self, index: usize) -> Option<&WrapperTxInQueue> {
            self.0.get(index)
        }
    }
}

#[cfg(feature = "ferveo-tpke")]
pub use tx_queue::{TxQueue, WrapperTxInQueue};
