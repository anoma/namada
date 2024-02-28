//! All the states of the [`BlockAllocator`] state machine,
//! over the extent of a Tendermint consensus round
//! block proposal.
//!
//! # States
//!
//! The state machine moves through the following state DAG:
//!
//! 1. [`BuildingEncryptedTxBatch`] - the initial state. In this state, we
//!    populate a block with DKG encrypted txs. This state supports two modes of
//!    operation, which you can think of as two sub-states:
//!   * [`WithoutEncryptedTxs`] - When this mode is active, no encrypted txs are
//!     included in a block proposal.
//!   * [`WithEncryptedTxs`] - When this mode is active, we are able to include
//!     encrypted txs in a block proposal.
//! 2. [`BuildingDecryptedTxBatch`] - the second state. In this state, we
//!    populate a block with DKG decrypted txs.
//! 3. [`BuildingProtocolTxBatch`] - the third state. In this state, we populate
//!    a block with protocol txs.

mod decrypted_txs;
mod encrypted_txs;
mod protocol_txs;

use super::{AllocFailure, BlockAllocator};

/// Convenience wrapper for a [`BlockAllocator`] state that allocates
/// encrypted transactions.
#[allow(dead_code)]
pub enum EncryptedTxBatchAllocator {
    WithEncryptedTxs(
        BlockAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>>,
    ),
    WithoutEncryptedTxs(
        BlockAllocator<BuildingEncryptedTxBatch<WithoutEncryptedTxs>>,
    ),
}

/// The leader of the current Tendermint round is building
/// a new batch of DKG decrypted transactions.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::block_alloc::states`].
pub enum BuildingDecryptedTxBatch {}

/// The leader of the current Tendermint round is building
/// a new batch of Namada protocol transactions.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::block_alloc::states`].
pub enum BuildingProtocolTxBatch {}

/// The leader of the current Tendermint round is building
/// a new batch of DKG encrypted transactions.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::block_alloc::states`].
pub struct BuildingEncryptedTxBatch<Mode> {
    /// One of [`WithEncryptedTxs`] and [`WithoutEncryptedTxs`].
    _mode: Mode,
}

/// Allow block proposals to include encrypted txs.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::block_alloc::states`].
pub enum WithEncryptedTxs {}

/// Prohibit block proposals from including encrypted txs.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::block_alloc::states`].
pub enum WithoutEncryptedTxs {}

/// Try to allocate a new transaction on a [`BlockAllocator`] state.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::block_alloc::states`].
pub trait TryAlloc {
    type Resources<'tx>;

    /// Try to allocate resources for a new transaction.
    fn try_alloc(
        &mut self,
        resource_required: Self::Resources<'_>,
    ) -> Result<(), AllocFailure>;
}

/// Represents a state transition in the [`BlockAllocator`] state machine.
///
/// This trait should not be used directly. Instead, consider using
/// [`NextState`].
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::block_alloc::states`].
pub trait NextStateImpl<Transition = ()> {
    /// The next state in the [`BlockAllocator`] state machine.
    type Next;

    /// Transition to the next state in the [`BlockAllocator`] state
    /// machine.
    fn next_state_impl(self) -> Self::Next;
}

/// Convenience extension of [`NextStateImpl`], to transition to a new
/// state with a null transition function.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::block_alloc::states`].
pub trait NextState: NextStateImpl {
    /// Transition to the next state in the [`BlockAllocator`] state,
    /// using a null transiiton function.
    #[inline]
    fn next_state(self) -> Self::Next
    where
        Self: Sized,
    {
        self.next_state_impl()
    }
}

impl<S> NextState for S where S: NextStateImpl {}
