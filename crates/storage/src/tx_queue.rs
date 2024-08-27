//! Transaction queue

use namada_core::borsh::{BorshDeserialize, BorshSerialize};
pub use namada_core::ethereum_events::EthereumEvent;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;

/// Expired transaction kinds.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshDeserializer)]
pub enum ExpiredTx {
    /// Broadcast the given Ethereum event.
    EthereumEvent(EthereumEvent),
}

/// Queue of expired transactions that need to be retransmitted.
#[derive(
    Default, Clone, Debug, BorshSerialize, BorshDeserialize, BorshDeserializer,
)]
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
