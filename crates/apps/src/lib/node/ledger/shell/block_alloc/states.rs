//! All the states of the [`BlockAllocator`] state machine,
//! over the extent of a Tendermint consensus round
//! block proposal.
//!
//! # States
//!
//! The state machine moves through the following state DAG:
//!
//! 1. [`BuildingProtocolTxBatch`] - the initial state. In
//!    this state, we populate a block with protocol txs.
//! 2. [`BuildingTxBatch`] - the second state. In
//!    this state, we populate a block with non-protocol txs.
//! 3. [`BuildingProtocolTxBatch`] - we return to this state to
//!    fill up any remaining block space if possible.

mod normal_txs;
mod protocol_txs;

use super::AllocFailure;

/// The leader of the current Tendermint round is building
/// a new batch of protocol txs.
///
/// This happens twice, in the first stage, we fill up to 1/2
/// of the block. At the end of allocating user txs, we fill
/// up any remaining space with un-allocated protocol txs.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::block_alloc::states`].
pub struct BuildingProtocolTxBatch<Mode> {
    /// One of [`WithEncryptedTxs`] and [`WithoutEncryptedTxs`].
    _mode: Mode,
}

/// Allow block proposals to include user submitted txs.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::block_alloc::states`].
pub enum WithNormalTxs {}

/// Allow block proposals to include encrypted txs.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::block_alloc::states`].
pub enum WithoutNormalTxs {}

/// The leader of the current Tendermint round is building
/// a new batch of user submitted (non-protocol) transactions.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::block_alloc::states`].
pub struct BuildingTxBatch {}

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
