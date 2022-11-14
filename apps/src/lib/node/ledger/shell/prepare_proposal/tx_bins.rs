//! Primitives that facilitate keeping track of the number
//! of bytes utilized by some Tendermint consensus round's proposal.
//!
//! This is important, because Tendermint places an upper bound
//! on the size of a block, rejecting blocks whose size exceeds
//! the limit stated in [`RequestPrepareProposal`].
//!
//! In the current implementation, each kind of transaction in
//! Namada gets a portion of (i.e. threshold over) the total
//! allotted space.

// TODO: what if a tx has a size greater than the threshold for
// its bin? how do we handle this? if we keep it in the mempool
// forever, it'll be a DoS vec, as we can make nodes run out of
// memory! maybe we should allow block decisions for txs that are
// too big to fit in their respective bin? in these special block
// decisions, we would only decide proposals with "large" txs

// TODO: refactor our measure of space to also reflect gas costs.
// the total gas of all chosen txs cannot exceed the configured max
// gas per block, otherwise a proposal will be rejected!

use std::marker::PhantomData;

use num_rational::Ratio;

use crate::facade::tendermint_proto::abci::RequestPrepareProposal;

/// All status responses from trying to allocate block space for a tx.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AllocStatus {
    /// The transaction is able to be included in the current block.
    Accepted,
    /// The transaction can only be included in an upcoming block.
    Rejected,
    /// The transaction would overflow the allotted bin space,
    /// therefore it needs to be handled separately.
    OverflowsBin,
}

/// Allotted space for a batch of transactions in some proposed block,
/// measured in bytes.
///
/// We keep track of the current space utilized by:
///
///   - Protocol transactions.
///   - DKG decrypted transactions.
///   - DKG encrypted transactions.
#[derive(Default)]
pub struct TxAllottedSpace<State> {
    /// The current state of the [`TxAllottedSpace`] state machine.
    _state: PhantomData<*const State>,
    /// The total space Tendermint has allotted to the
    /// application for the current block height.
    bytes_provided_by_tendermint: u64,
    /// The current space utilized by protocol transactions.
    protocol_txs: TxBin,
    /// The current space utilized by DKG encrypted transactions.
    encrypted_txs: TxBin,
    /// The current space utilized by DKG decrypted transactions.
    decrypted_txs: TxBin,
}

impl From<&RequestPrepareProposal>
    for TxAllottedSpace<states::BuildingDecryptedTxBatch>
{
    #[inline]
    fn from(req: &RequestPrepareProposal) -> Self {
        let tendermint_max_block_space_in_bytes = req.max_tx_bytes as u64;
        Self::init(tendermint_max_block_space_in_bytes)
    }
}

impl TxAllottedSpace<states::BuildingDecryptedTxBatch> {
    /// Construct a new [`TxAllottedSpace`], with an upper bound
    /// on the max number of txs in a block defined by Tendermint.
    #[inline]
    pub fn init(tendermint_max_block_space_in_bytes: u64) -> Self {
        let max = tendermint_max_block_space_in_bytes;
        Self {
            _state: PhantomData,
            bytes_provided_by_tendermint: max,
            protocol_txs: TxBin::default(),
            encrypted_txs: TxBin::default(),
            decrypted_txs: TxBin::init(max),
        }
    }

    /// Try to allocate space for a new DKG decrypted transaction.
    #[allow(dead_code)]
    #[inline]
    pub fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        self.decrypted_txs.try_dump(tx)
    }

    /// Try to allocate space for a new batch of DKG decrypted transactions.
    #[allow(dead_code)]
    #[inline]
    pub fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.decrypted_txs.try_dump_all(txs)
    }

    /// Transition to the next state in the [`TxAllottedSpace`] state machine.
    ///
    /// For more info, read the module docs of
    /// [`crate::node::ledger::shell::prepare_proposal::tx_bins::states`].
    #[allow(dead_code)]
    #[inline]
    pub fn next_state(
        self,
    ) -> TxAllottedSpace<states::BuildingProtocolTxBatch> {
        let Self {
            bytes_provided_by_tendermint,
            mut protocol_txs,
            encrypted_txs,
            decrypted_txs,
            ..
        } = self;
        // TODO: reserve space for protocol txs
        protocol_txs.allotted_space_in_bytes = 0;
        TxAllottedSpace {
            _state: PhantomData,
            bytes_provided_by_tendermint,
            protocol_txs,
            encrypted_txs,
            decrypted_txs,
        }
    }
}

// WIP
impl<State> TxAllottedSpace<State> {
    /// Return uninitialized space in tx bins, resulting from ratio conversions.
    ///
    /// This method should not be used outside of [`TxAllottedSpace`]
    /// instance construction or unit testing.
    #[allow(dead_code)]
    fn uninitialized_space_in_bytes(&self) -> u64 {
        let total_bin_space = self.protocol_txs.allotted_space_in_bytes
            + self.encrypted_txs.allotted_space_in_bytes
            + self.decrypted_txs.allotted_space_in_bytes;
        self.bytes_provided_by_tendermint - total_bin_space
    }

    /// The total space, in bytes, occupied by each transaction.
    #[inline]
    pub fn occupied_space_in_bytes(&self) -> u64 {
        self.protocol_txs.current_space_in_bytes
            + self.encrypted_txs.current_space_in_bytes
            + self.decrypted_txs.current_space_in_bytes
    }

    /// Return the amount, in bytes, of free space in this
    /// [`TxAllottedSpace`].
    #[inline]
    pub fn free_space_in_bytes(&self) -> u64 {
        self.bytes_provided_by_tendermint - self.occupied_space_in_bytes()
    }

    /// Checks if this [`TxAllottedSpace`] has any free space remaining.
    #[allow(dead_code)]
    #[inline]
    pub fn has_free_space(&self) -> bool {
        self.free_space_in_bytes() > 0
    }
}

// all allocation boilerplate code shall
// be shunned to this impl block -- shame!
//
// WIP
impl<State> TxAllottedSpace<State> {
    /// Try to allocate space for a new protocol transaction.
    #[allow(dead_code)]
    #[inline]
    pub fn try_alloc_protocol_tx(&mut self, tx: &[u8]) -> AllocStatus {
        self.protocol_txs.try_dump(tx)
    }

    /// Try to allocate space for a new batch of protocol transactions.
    #[allow(dead_code)]
    #[inline]
    pub fn try_alloc_protocol_tx_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.protocol_txs.try_dump_all(txs)
    }

    // --------------------------------------------------- //

    /// Try to allocate space for a new DKG encrypted transaction.
    #[allow(dead_code)]
    #[inline]
    pub fn try_alloc_encrypted_tx(&mut self, tx: &[u8]) -> AllocStatus {
        self.encrypted_txs.try_dump(tx)
    }

    /// Try to allocate space for a new batch of DKG encrypted transactions.
    #[allow(dead_code)]
    #[inline]
    pub fn try_alloc_encrypted_tx_batch<'tx, T>(
        &mut self,
        txs: T,
    ) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.encrypted_txs.try_dump_all(txs)
    }
}

/// Allotted space for a batch of transactions of the same kind in some
/// proposed block, measured in bytes.
#[derive(Copy, Clone, Default)]
struct TxBin {
    /// The current space utilized by the batch of transactions.
    current_space_in_bytes: u64,
    /// The maximum space the batch of transactions may occupy.
    allotted_space_in_bytes: u64,
}

impl TxBin {
    /// Construct a new [`TxBin`], with an upper bound on the max number
    /// of storable txs defined by a ratio over `max_bytes`.
    #[inline]
    #[allow(dead_code)]
    fn init_over_ratio(max_bytes: u64, frac: Ratio<u64>) -> Self {
        let allotted_space_in_bytes = (frac * max_bytes).to_integer();
        Self {
            allotted_space_in_bytes,
            current_space_in_bytes: 0,
        }
    }

    /// Construct a new [`TxBin`], with a capacity of `max_bytes`.
    #[inline]
    fn init(max_bytes: u64) -> Self {
        Self {
            allotted_space_in_bytes: max_bytes,
            current_space_in_bytes: 0,
        }
    }

    /// Try to dump a new transaction into this [`TxBin`].
    ///
    /// Signal the caller if the tx is larger than its max
    /// allotted bin space.
    #[inline]
    fn try_dump(&mut self, tx: &[u8]) -> AllocStatus {
        let tx_len = tx.len() as u64;
        if tx_len > self.allotted_space_in_bytes {
            return AllocStatus::OverflowsBin;
        }
        let occupied = self.current_space_in_bytes + tx_len;
        if occupied <= self.allotted_space_in_bytes {
            self.current_space_in_bytes = occupied;
            AllocStatus::Accepted
        } else {
            AllocStatus::Rejected
        }
    }

    /// Try to dump a new batch of transactions into this [`TxBin`].
    ///
    /// If an allocation fails, rollback the state of the [`TxBin`],
    /// and return the respective status of the failure.
    #[inline]
    fn try_dump_all<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        let mut space_diff = 0;
        for tx in txs {
            match self.try_dump(tx) {
                AllocStatus::Accepted => space_diff += tx.len() as u64,
                status
                @ (AllocStatus::Rejected | AllocStatus::OverflowsBin) => {
                    self.current_space_in_bytes -= space_diff;
                    return status;
                }
            }
        }
        AllocStatus::Accepted
    }
}

mod thres {
    //! Transaction allotment thresholds.

    use num_rational::Ratio;

    /// The threshold over Tendermint's allotted space for protocol txs.
    #[allow(dead_code)]
    pub const PROTOCOL_TX: Ratio<u64> = Ratio::new_raw(1, 3);

    /// The threshold over Tendermint's allotted space for DKG encrypted txs.
    #[allow(dead_code)]
    pub const ENCRYPTED_TX: Ratio<u64> = Ratio::new_raw(1, 3);

    /// The threshold over Tendermint's allotted space for DKG decrypted txs.
    ///
    /// This value should always be the same as [`ENCRYPTED_TX`].
    /// The reason for which is that during the decision process of
    /// block height `H`, we must include the same number of decrypted
    /// txs as the number of encrypted txs proposed during block height
    /// `H - 1`.
    #[allow(dead_code)]
    pub const DECRYPTED_TX: Ratio<u64> = ENCRYPTED_TX;
}

// hacky workaround to get module docstrings formatted properly
#[rustfmt::skip]
mod states {
    //! All the states of the [`TxAllottedSpace`] state machine,
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
    //!   1. [`WithoutEncryptedTxs`] - When this mode is active, no encrypted txs
    //!      are included in a block proposal.
    //!   2. [`WithEncryptedTxs`] - When this mode is active, we are able
    //!      to include encrypted txs in a block proposal.
    //! 4. [`FillingRemainingSpace`] - the fourth and final state.
    //!    During this phase, we fill all remaining block space with arbitrary
    //!    transactions that haven't been included yet. This state supports the
    //!    same two modes of operation defined above.

    #[allow(unused_imports)]
    use super::TxAllottedSpace;

    #[doc(inline)]
    pub use super::states_impl::*;
}

mod states_impl {
    //! Implements [`super::states`].

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
}

// ```ignore
// #[cfg(test)]
// mod tests {
//     use std::cell::RefCell;
//
//     use proptest::prelude::*;
//
//     use super::*;
//     use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;
//
//     /// Proptest generated txs.
//     #[derive(Debug)]
//     struct PropTx {
//         tendermint_max_block_space_in_bytes: u64,
//         protocol_txs: Vec<TxBytes>,
//         encrypted_txs: Vec<TxBytes>,
//         decrypted_txs: Vec<TxBytes>,
//     }
//
//     /// Check if the sum of all individual tx thresholds does
//     /// not exceed one.
//     ///
//     /// This is important, because we do not want to exceed
//     /// the maximum block size in Tendermint, and get randomly
//     /// rejected blocks.
//     #[test]
//     fn test_tx_thres_doesnt_exceed_one() {
//         let sum =
//             thres::PROTOCOL_TX + thres::ENCRYPTED_TX + thres::DECRYPTED_TX;
//         assert_eq!(sum.to_integer(), 1);
//     }
//
//     proptest! {
//         /// Check if we reject a tx when its respective bin
//         /// capacity has been reached on a [`TxAllottedSpace`].
//         #[test]
//         fn test_reject_tx_on_bin_cap_reached(max in prop::num::u64::ANY) {
//             proptest_reject_tx_on_bin_cap_reached(max)
//         }
//
//         /// Check if the sum of all individual bin allotments for a
//         /// [`TxAllottedSpace`] corresponds to the total space ceded
//         /// by Tendermint.
//         #[test]
//         fn test_bin_capacity_eq_provided_space(max in prop::num::u64::ANY) {
//             proptest_bin_capacity_eq_provided_space(max)
//         }
//
//         /// Test that dumping txs whose total combined size
//         /// is less than the bin cap does not fill up the bin.
//         #[test]
//         fn test_tx_dump_doesnt_fill_up_bin(args in arb_transactions()) {
//             proptest_tx_dump_doesnt_fill_up_bin(args)
//         }
//     }
//
//     /// Implementation of [`test_reject_tx_on_bin_cap_reached`].
//     fn proptest_reject_tx_on_bin_cap_reached(
//         tendermint_max_block_space_in_bytes: u64,
//     ) {
//         let mut bins =
//             TxAllottedSpace::init(tendermint_max_block_space_in_bytes);
//
//         // fill the entire bin of decrypted txs
//         bins.decrypted_txs.current_space_in_bytes =
//             bins.decrypted_txs.allotted_space_in_bytes;
//
//         // make sure we can't dump any new decrypted txs in the bin
//         assert_eq!(
//             bins.try_alloc_decrypted_tx(b"arbitrary tx bytes"),
//             AllocStatus::Rejected
//         );
//     }
//
//     /// Implementation of [`test_bin_capacity_eq_provided_space`].
//     fn proptest_bin_capacity_eq_provided_space(
//         tendermint_max_block_space_in_bytes: u64,
//     ) {
//         let bins = TxAllottedSpace::init(tendermint_max_block_space_in_bytes);
//         assert_eq!(0, bins.uninitialized_space_in_bytes());
//     }
//
//     /// Implementation of [`test_tx_dump_doesnt_fill_up_bin`].
//     fn proptest_tx_dump_doesnt_fill_up_bin(args: PropTx) {
//         let PropTx {
//             tendermint_max_block_space_in_bytes,
//             protocol_txs,
//             encrypted_txs,
//             decrypted_txs,
//         } = args;
//         let bins = RefCell::new(TxAllottedSpace::init(
//             tendermint_max_block_space_in_bytes,
//         ));
//
//         // produce new txs until we fill up the bins
//         //
//         // TODO: ideally the proptest strategy would already return
//         // txs whose total added size would be bounded
//         let protocol_txs = protocol_txs.into_iter().take_while(|tx| {
//             let bin = bins.borrow().protocol_txs;
//             let new_size = bin.current_space_in_bytes + tx.len() as u64;
//             new_size < bin.allotted_space_in_bytes
//         });
//         let encrypted_txs = encrypted_txs.into_iter().take_while(|tx| {
//             let bin = bins.borrow().encrypted_txs;
//             let new_size = bin.current_space_in_bytes + tx.len() as u64;
//             new_size < bin.allotted_space_in_bytes
//         });
//         let decrypted_txs = decrypted_txs.into_iter().take_while(|tx| {
//             let bin = bins.borrow().decrypted_txs;
//             let new_size = bin.current_space_in_bytes + tx.len() as u64;
//             new_size < bin.allotted_space_in_bytes
//         });
//
//         // make sure we can keep dumping txs,
//         // without filling up the bins
//         for tx in protocol_txs {
//             assert_eq!(
//                 bins.borrow_mut().try_alloc_protocol_tx(&tx),
//                 AllocStatus::Accepted
//             );
//         }
//         for tx in encrypted_txs {
//             assert_eq!(
//                 bins.borrow_mut().try_alloc_encrypted_tx(&tx),
//                 AllocStatus::Accepted
//             );
//         }
//         for tx in decrypted_txs {
//             assert_eq!(
//                 bins.borrow_mut().try_alloc_decrypted_tx(&tx),
//                 AllocStatus::Accepted
//             );
//         }
//     }
//
//     prop_compose! {
//         /// Generate arbitrarily sized txs of different kinds.
//         fn arb_transactions()
//             // create base strategies
//             (
//                 (tendermint_max_block_space_in_bytes, protocol_tx_max_bin_size, encrypted_tx_max_bin_size,
//                  decrypted_tx_max_bin_size) in arb_max_bin_sizes(),
//             )
//             // compose strategies
//             (
//                 tendermint_max_block_space_in_bytes in Just(tendermint_max_block_space_in_bytes),
//                 protocol_txs in arb_tx_list(protocol_tx_max_bin_size),
//                 encrypted_txs in arb_tx_list(encrypted_tx_max_bin_size),
//                 decrypted_txs in arb_tx_list(decrypted_tx_max_bin_size),
//             )
//             -> PropTx {
//                 PropTx {
//                     tendermint_max_block_space_in_bytes,
//                     protocol_txs,
//                     encrypted_txs,
//                     decrypted_txs,
//                 }
//             }
//     }
//
//     /// Return random bin sizes for a [`TxAllottedSpace`].
//     fn arb_max_bin_sizes() -> impl Strategy<Value = (u64, usize, usize, usize)>
//     {
//         const MAX_BLOCK_SIZE_BYTES: u64 = 1000;
//         (1..=MAX_BLOCK_SIZE_BYTES).prop_map(
//             |tendermint_max_block_space_in_bytes| {
//                 (
//                     tendermint_max_block_space_in_bytes,
//                     (thres::PROTOCOL_TX * tendermint_max_block_space_in_bytes)
//                         .to_integer() as usize,
//                     (thres::ENCRYPTED_TX * tendermint_max_block_space_in_bytes)
//                         .to_integer() as usize,
//                     (thres::DECRYPTED_TX * tendermint_max_block_space_in_bytes)
//                         .to_integer() as usize,
//                 )
//             },
//         )
//     }
//
//     /// Return a list of txs.
//     fn arb_tx_list(max_bin_size: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
//         const MAX_TX_NUM: usize = 64;
//         let tx = prop::collection::vec(prop::num::u8::ANY, 0..=max_bin_size);
//         prop::collection::vec(tx, 0..=MAX_TX_NUM)
//     }
// }
// ```
