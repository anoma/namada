//! All the states of the [`BlockSpaceAllocator`] state machine,
//! over the extent of a Tendermint consensus round
//! block proposal.
//!
//! # States
//!
//! The state machine moves through the following state DAG:
//!
//! 1. [`BuildingDecryptedTxBatch`] - the initial state. In
//!    this state, we populate a block with DKG decrypted txs.
//! 2. [`BuildingProtocolTxBatch`] - the second state. In
//!    this state, we populate a block with protocol txs.
//! 3. [`BuildingEncryptedTxBatch`] - the third state. In
//!    this state, we populate a block with DKG encrypted txs.
//!    This state supports two modes of operation, which you can
//!    think of as two states diverging from [`BuildingProtocolTxBatch`]:
//!   * [`WithoutEncryptedTxs`] - When this mode is active, no encrypted txs are
//!     included in a block proposal.
//!   * [`WithEncryptedTxs`] - When this mode is active, we are able to include
//!     encrypted txs in a block proposal.
//! 4. [`FillingRemainingSpace`] - the fourth and final state.
//!    During this phase, we fill all remaining block space with arbitrary
//!    protocol transactions that haven't been included in a block, yet.

mod decrypted_txs;
mod encrypted_txs;
mod protocol_txs;
mod remaining_txs;

use super::{AllocFailure, BlockSpaceAllocator};

/// Convenience wrapper for a [`BlockSpaceAllocator`] state that allocates
/// encrypted transactions.
#[allow(dead_code)]
pub enum EncryptedTxBatchAllocator {
    WithEncryptedTxs(
        BlockSpaceAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>>,
    ),
    WithoutEncryptedTxs(
        BlockSpaceAllocator<BuildingEncryptedTxBatch<WithoutEncryptedTxs>>,
    ),
}

/// The leader of the current Tendermint round is building
/// a new batch of DKG decrypted transactions.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::block_space_alloc::states`].
pub enum BuildingDecryptedTxBatch {}

/// The leader of the current Tendermint round is building
/// a new batch of Namada protocol transactions.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::block_space_alloc::states`].
pub enum BuildingProtocolTxBatch {}

/// The leader of the current Tendermint round is building
/// a new batch of DKG encrypted transactions.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::block_space_alloc::states`].
pub struct BuildingEncryptedTxBatch<Mode> {
    /// One of [`WithEncryptedTxs`] and [`WithoutEncryptedTxs`].
    _mode: Mode,
}

/// The leader of the current Tendermint round is populating
/// all remaining space in a block proposal with arbitrary
/// protocol transactions that haven't been included in the
/// block, yet.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::block_space_alloc::states`].
pub enum FillingRemainingSpace {}

/// Allow block proposals to include encrypted txs.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::block_space_alloc::states`].
pub enum WithEncryptedTxs {}

/// Prohibit block proposals from including encrypted txs.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::block_space_alloc::states`].
pub enum WithoutEncryptedTxs {}

/// Try to allocate a new transaction on a [`BlockSpaceAllocator`] state.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::block_space_alloc::states`].
pub trait TryAlloc {
    /// Try to allocate space for a new transaction.
    fn try_alloc(&mut self, tx: &[u8]) -> Result<(), AllocFailure>;
}

/// Represents a state transition in the [`BlockSpaceAllocator`] state machine.
///
/// This trait should not be used directly. Instead, consider using one of
/// [`NextState`], [`NextStateWithEncryptedTxs`] or
/// [`NextStateWithoutEncryptedTxs`].
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::block_space_alloc::states`].
pub trait NextStateImpl<Transition = ()> {
    /// The next state in the [`BlockSpaceAllocator`] state machine.
    type Next;

    /// Transition to the next state in the [`BlockSpaceAllocator`] state
    /// machine.
    fn next_state_impl(self) -> Self::Next;
}

/// Convenience extension of [`NextStateImpl`], to transition to a new
/// state with encrypted txs in a block.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::block_space_alloc::states`].
pub trait NextStateWithEncryptedTxs: NextStateImpl<WithEncryptedTxs> {
    /// Transition to the next state in the [`BlockSpaceAllocator`] state,
    /// ensuring we include encrypted txs in a block.
    #[inline]
    fn next_state_with_encrypted_txs(self) -> Self::Next
    where
        Self: Sized,
    {
        self.next_state_impl()
    }
}

impl<S> NextStateWithEncryptedTxs for S where S: NextStateImpl<WithEncryptedTxs> {}

/// Convenience extension of [`NextStateImpl`], to transition to a new
/// state without encrypted txs in a block.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::block_space_alloc::states`].
pub trait NextStateWithoutEncryptedTxs:
    NextStateImpl<WithoutEncryptedTxs>
{
    /// Transition to the next state in the [`BlockSpaceAllocator`] state,
    /// ensuring we do not include encrypted txs in a block.
    #[inline]
    fn next_state_without_encrypted_txs(self) -> Self::Next
    where
        Self: Sized,
    {
        self.next_state_impl()
    }
}

impl<S> NextStateWithoutEncryptedTxs for S where
    S: NextStateImpl<WithoutEncryptedTxs>
{
}

/// Convenience extension of [`NextStateImpl`], to transition to a new
/// state with a null transition function.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::block_space_alloc::states`].
pub trait NextState: NextStateImpl {
    /// Transition to the next state in the [`BlockSpaceAllocator`] state,
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
