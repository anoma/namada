use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::ethereum_events::EthereumEvent;
use namada_gas::Gas;
use namada_tx::Tx;

/// A wrapper for `crate::types::transaction::WrapperTx` to conditionally
/// add `has_valid_pow` flag for only used in testnets.
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct TxInQueue {
    /// Wrapper tx
    pub tx: Tx,
    /// The available gas remaining for the inner tx (for gas accounting).
    /// This allows for a more detailed logging about the gas used by the
    /// wrapper and that used by the inner
    pub gas: Gas,
}

#[derive(Default, Debug, Clone, BorshDeserialize, BorshSerialize)]
/// Wrapper txs to be decrypted in the next block proposal
pub struct TxQueue(std::collections::VecDeque<TxInQueue>);

impl TxQueue {
    /// Add a new wrapper at the back of the queue
    pub fn push(&mut self, wrapper: TxInQueue) {
        self.0.push_back(wrapper);
    }

    /// Remove the wrapper at the head of the queue
    pub fn pop(&mut self) -> Option<TxInQueue> {
        self.0.pop_front()
    }

    /// Get an iterator over the queue
    pub fn iter(&self) -> impl std::iter::Iterator<Item = &TxInQueue> {
        self.0.iter()
    }

    /// Check if there are any txs in the queue
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get reference to the element at the given index.
    /// Returns [`None`] if index exceeds the queue lenght.
    pub fn get(&self, index: usize) -> Option<&TxInQueue> {
        self.0.get(index)
    }
}

/// Expired transaction kinds.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum ExpiredTx {
    /// Broadcast the given Ethereum event.
    EthereumEvent(EthereumEvent),
}

/// Queue of expired transactions that need to be retransmitted.
#[derive(Default, Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ExpiredTxsQueue {
    inner: Vec<ExpiredTx>,
}

impl ExpiredTxsQueue {
    /// Push a new transaction to the back of the queue.
    #[inline]
    pub fn push(&mut self, tx: ExpiredTx) {
        self.inner.push(tx);
    }

    /// Consume all the transactions in the queue.
    #[inline]
    pub fn drain(&mut self) -> impl Iterator<Item = ExpiredTx> + '_ {
        self.inner.drain(..)
    }
}
