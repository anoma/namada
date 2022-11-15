//! All the states of the [`BlockSpaceAllocator`] state machine,
//! over the extent of a Tendermint consensus round
//! block proposal.
//!
//! # States
//!
//! The state machine moves through the following states:
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
//!    transactions that haven't been included yet. This state supports the
//!    same two modes of operation defined above.

use super::AllocStatus;
#[allow(unused_imports)]
use super::BlockSpaceAllocator;

/// The leader of the current Tendermint round is building
/// a new batch of DKG decrypted transactions.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::tx_bins::states`].
#[allow(dead_code)]
pub enum BuildingDecryptedTxBatch {}

/// The leader of the current Tendermint round is building
/// a new batch of Namada protocol transactions.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::tx_bins::states`].
#[allow(dead_code)]
pub enum BuildingProtocolTxBatch {}

/// The leader of the current Tendermint round is building
/// a new batch of DKG encrypted transactions.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::tx_bins::states`].
#[allow(dead_code)]
pub struct BuildingEncryptedTxBatch<Mode> {
    /// One of [`WithEncryptedTxs`] and [`WithoutEncryptedTxs`].
    _mode: Mode,
}

/// The leader of the current Tendermint round is populating
/// all remaining space in a block proposal with arbitrary
/// transactions.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::tx_bins::states`].
#[allow(dead_code)]
pub struct FillingRemainingSpace<Mode> {
    /// One of [`WithEncryptedTxs`] and [`WithoutEncryptedTxs`].
    _mode: Mode,
}

/// Allow block proposals to include encrypted txs.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::tx_bins::states`].
#[allow(dead_code)]
pub enum WithEncryptedTxs {}

/// Prohibit block proposals from including encrypted txs.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::tx_bins::states`].
#[allow(dead_code)]
pub enum WithoutEncryptedTxs {}

/// Represents a state in the [`BlockSpaceAllocator`] state machine.
///
/// For more info, read the module docs of
/// [`crate::node::ledger::shell::prepare_proposal::tx_bins::states`].
pub trait State<Transition = ()> {
    /// The next state in the [`BlockSpaceAllocator`] state machine.
    type Next;

    /// Try to allocate space for a new transaction.
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus;

    /// Try to allocate space for a new batch of transactions.
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx;

    /// Transition to the next state in the [`BlockSpaceAllocator`] state
    /// machine.
    fn next_state(self) -> Self::Next;
}

/// Convenience extension of [`State`], to transition to a new
/// state with encrypted txs in a block.
pub trait StateWithEncryptedTxs: State<WithEncryptedTxs> {
    /// Transition to the next state in the [`BlockSpaceAllocator`] state,
    /// ensuring we include encrypted txs in a block.
    #[inline]
    fn next_state_with_encrypted_txs(self) -> Self::Next
    where
        Self: Sized,
    {
        self.next_state()
    }
}

impl<S> StateWithEncryptedTxs for S where S: State<WithEncryptedTxs> {}

/// Convenience extension of [`State`], to transition to a new
/// state without encrypted txs in a block.
pub trait StateWithoutEncryptedTxs: State<WithoutEncryptedTxs> {
    /// Transition to the next state in the [`BlockSpaceAllocator`] state,
    /// ensuring we do not include encrypted txs in a block.
    #[inline]
    fn next_state_without_encrypted_txs(self) -> Self::Next
    where
        Self: Sized,
    {
        self.next_state()
    }
}

impl<S> StateWithoutEncryptedTxs for S where S: State<WithoutEncryptedTxs> {}
