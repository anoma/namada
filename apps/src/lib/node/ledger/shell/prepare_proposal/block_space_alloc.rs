//! Primitives that facilitate keeping track of the number
//! of bytes utilized by some Tendermint consensus round's proposal.
//!
//! This is important, because Tendermint places an upper bound
//! on the size of a block, rejecting blocks whose size exceeds
//! the limit stated in [`RequestPrepareProposal`].
//!
//! The code in this module doesn't perform any deserializing to
//! verify if we are, in fact, allocating space for the correct
//! kind of tx for the current [`BlockSpaceAllocator`] state. It
//! is up to the user to dispatch the correct kind of tx into the
//! current state of the allocator.
//!
//! # How space is allocated
//!
//! In the current implementation, we allocate space for transactions
//! in the following order of preference:
//!
//! - First, we allocate space for DKG decrypted txs.
//! - Next, we allocate space for protocol txs. Protocol txs get 1/3 of the
//!   block space allotted to them.
//! - Finally, we allocate space for DKG encrypted txs.
//! - If any space remains, we try to fit other smaller txs in the block.
//!
//! Since decrypted txs will utilize at most as much space as
//! encrypted txs will utilize, and we allocate 1/3 of space
//! that has already been taken up by decrypted txs to protocol
//! txs, we roughly divide the block space in 3 for each kind
//! of major tx type.

pub mod states;

// TODO: what if a tx has a size greater than the threshold for
// its bin? how do we handle this? if we keep it in the mempool
// forever, it'll be a DoS vec, as we can make nodes run out of
// memory! maybe we should allow block decisions for txs that are
// too big to fit in their respective bin? in these special block
// decisions, we would only decide proposals with "large" txs??
//
// MAYBE: in the state machine impl, reset to beginning state, and
// and alloc space for large tx right at the start. the problem with
// this is that then we may not have enough space for decrypted txs

// TODO: panic if we don't have enough space reserved for a
// decrypted tx; in theory, we should always have enough space
// reserved for decrypted txs, given the invariants of the state
// machine

// TODO: refactor our measure of space to also reflect gas costs.
// the total gas of all chosen txs cannot exceed the configured max
// gas per block, otherwise a proposal will be rejected!

use std::marker::PhantomData;

use num_rational::Ratio;

use crate::facade::tendermint_proto::abci::RequestPrepareProposal;

/// All status responses from trying to allocate block space for a tx.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AllocStatus<'tx> {
    /// The transaction is able to be included in the current block.
    Accepted,
    /// The transaction can only be included in an upcoming block.
    Rejected { tx: &'tx [u8], space_left: u64 },
    /// The transaction would overflow the allotted bin space,
    /// therefore it needs to be handled separately.
    OverflowsBin { tx: &'tx [u8], bin_size: u64 },
}

/// Allotted space for a batch of transactions in some proposed block,
/// measured in bytes.
///
/// We keep track of the current space utilized by:
///
///   - Protocol transactions.
///   - DKG decrypted transactions.
///   - DKG encrypted transactions.
#[derive(Debug, Default)]
pub struct BlockSpaceAllocator<State> {
    /// The current state of the [`BlockSpaceAllocator`] state machine.
    _state: PhantomData<*const State>,
    /// The total space Tendermint has allotted to the
    /// application for the current block height.
    block: TxBin,
    /// The current space utilized by protocol transactions.
    protocol_txs: TxBin,
    /// The current space utilized by DKG encrypted transactions.
    encrypted_txs: TxBin,
    /// The current space utilized by DKG decrypted transactions.
    decrypted_txs: TxBin,
}

impl From<&RequestPrepareProposal>
    for BlockSpaceAllocator<states::BuildingDecryptedTxBatch>
{
    #[inline]
    fn from(req: &RequestPrepareProposal) -> Self {
        let tendermint_max_block_space_in_bytes = req.max_tx_bytes as u64;
        Self::init(tendermint_max_block_space_in_bytes)
    }
}

impl BlockSpaceAllocator<states::BuildingDecryptedTxBatch> {
    /// Construct a new [`BlockSpaceAllocator`], with an upper bound
    /// on the max size of all txs in a block defined by Tendermint.
    #[inline]
    pub fn init(tendermint_max_block_space_in_bytes: u64) -> Self {
        let max = tendermint_max_block_space_in_bytes;
        Self {
            _state: PhantomData,
            block: TxBin::init(max),
            protocol_txs: TxBin::default(),
            encrypted_txs: TxBin::default(),
            // decrypted txs can use as much space as needed; in practice,
            // we'll only need, at most, the amount of space reserved for
            // encrypted txs at the prev block height
            decrypted_txs: TxBin::init(max),
        }
    }
}

impl<State> BlockSpaceAllocator<State> {
    /// Return the amount of space left to initialize in all
    /// [`TxBin`] instances.
    ///
    /// This is calculated based on the difference between the Tendermint
    /// block space for a given round and the sum of the allotted space
    /// to each [`TxBin`] instance in a [`BlockSpaceAllocator`].
    #[inline]
    fn uninitialized_space_in_bytes(&self) -> u64 {
        let total_bin_space = self.protocol_txs.allotted_space_in_bytes
            + self.encrypted_txs.allotted_space_in_bytes
            + self.decrypted_txs.allotted_space_in_bytes;
        self.block.allotted_space_in_bytes - total_bin_space
    }

    /// Claim all the space used by the [`TxBin`] instances
    /// as block space.
    #[inline]
    fn claim_block_space(&mut self) {
        let used_space = self.protocol_txs.occupied_space_in_bytes
            + self.encrypted_txs.occupied_space_in_bytes
            + self.decrypted_txs.occupied_space_in_bytes;

        self.block.occupied_space_in_bytes = used_space;

        self.decrypted_txs = TxBin::default();
        self.protocol_txs = TxBin::default();
        self.encrypted_txs = TxBin::default();
    }
}

/// Allotted space for a batch of transactions of the same kind in some
/// proposed block, measured in bytes.
#[derive(Debug, Copy, Clone, Default)]
struct TxBin {
    /// The current space utilized by the batch of transactions.
    occupied_space_in_bytes: u64,
    /// The maximum space the batch of transactions may occupy.
    allotted_space_in_bytes: u64,
}

impl TxBin {
    /// Return a new [`TxBin`] with a total allotted space equal to the
    /// floor of the fraction `frac` of the available block space `max_bytes`.
    #[inline]
    fn init_over_ratio(max_bytes: u64, frac: Ratio<u64>) -> Self {
        let allotted_space_in_bytes = (frac * max_bytes).to_integer();
        Self {
            allotted_space_in_bytes,
            occupied_space_in_bytes: 0,
        }
    }

    /// Return the amount of space left in this [`TxBin`].
    #[inline]
    fn space_left_in_bytes(&self) -> u64 {
        self.allotted_space_in_bytes - self.occupied_space_in_bytes
    }

    /// Construct a new [`TxBin`], with a capacity of `max_bytes`.
    #[inline]
    fn init(max_bytes: u64) -> Self {
        Self {
            allotted_space_in_bytes: max_bytes,
            occupied_space_in_bytes: 0,
        }
    }

    /// Shrink the allotted space of this [`TxBin`] to whatever
    /// space is currently being utilized.
    #[inline]
    fn shrink_to_fit(&mut self) {
        self.allotted_space_in_bytes = self.occupied_space_in_bytes;
    }

    /// Try to dump a new transaction into this [`TxBin`].
    ///
    /// Signal the caller if the tx is larger than its max
    /// allotted bin space.
    fn try_dump<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
        let tx_len = tx.len() as u64;
        if tx_len > self.allotted_space_in_bytes {
            let bin_size = self.allotted_space_in_bytes;
            return AllocStatus::OverflowsBin { tx, bin_size };
        }
        let occupied = self.occupied_space_in_bytes + tx_len;
        if occupied <= self.allotted_space_in_bytes {
            self.occupied_space_in_bytes = occupied;
            AllocStatus::Accepted
        } else {
            let space_left = self.space_left_in_bytes();
            AllocStatus::Rejected { tx, space_left }
        }
    }

    /// Try to dump a new batch of transactions into this [`TxBin`].
    ///
    /// If an allocation fails, rollback the state of the [`TxBin`],
    /// and return the respective status of the failure.
    fn try_dump_all<'tx, T>(&mut self, txs: T) -> AllocStatus<'tx>
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        let mut space_diff = 0;
        for tx in txs {
            match self.try_dump(tx) {
                AllocStatus::Accepted => space_diff += tx.len() as u64,
                status @ (AllocStatus::Rejected { .. }
                | AllocStatus::OverflowsBin { .. }) => {
                    self.occupied_space_in_bytes -= space_diff;
                    return status;
                }
            }
        }
        AllocStatus::Accepted
    }
}

mod threshold {
    //! Transaction allotment thresholds.

    use num_rational::Ratio;

    /// The threshold over Tendermint's allotted space for all three
    /// (major) kinds of Namada transactions.
    #[cfg(test)]
    #[allow(dead_code)]
    pub const ONE_THIRD: Ratio<u64> = Ratio::new_raw(1, 3);

    /// Divide the allotted space in two.
    pub const ONE_HALF: Ratio<u64> = Ratio::new_raw(1, 2);
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use assert_matches::assert_matches;
    use proptest::prelude::*;

    use super::states::{NextState, NextStateWithEncryptedTxs, TryAlloc};
    use super::*;
    use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;

    /// Proptest generated txs.
    #[derive(Debug)]
    struct PropTx {
        tendermint_max_block_space_in_bytes: u64,
        protocol_txs: Vec<TxBytes>,
        encrypted_txs: Vec<TxBytes>,
        decrypted_txs: Vec<TxBytes>,
    }

    proptest! {
        /// Check if we reject a tx when its respective bin
        /// capacity has been reached on a [`BlockSpaceAllocator`].
        #[test]
        fn test_reject_tx_on_bin_cap_reached(max in prop::num::u64::ANY) {
            proptest_reject_tx_on_bin_cap_reached(max)
        }

        /// Check if the sum of all individual bin allotments for a
        /// [`BlockSpaceAllocator`] corresponds to the total space ceded
        /// by Tendermint.
        #[test]
        fn test_bin_capacity_eq_provided_space(max in prop::num::u64::ANY) {
            proptest_bin_capacity_eq_provided_space(max)
        }

        /// Test that dumping txs whose total combined size
        /// is less than the bin cap does not fill up the bin.
        #[test]
        fn test_tx_dump_doesnt_fill_up_bin(args in arb_transactions()) {
            proptest_tx_dump_doesnt_fill_up_bin(args)
        }
    }

    /// Implementation of [`test_reject_tx_on_bin_cap_reached`].
    fn proptest_reject_tx_on_bin_cap_reached(
        tendermint_max_block_space_in_bytes: u64,
    ) {
        let mut bins =
            BlockSpaceAllocator::init(tendermint_max_block_space_in_bytes);

        // fill the entire bin of decrypted txs
        bins.decrypted_txs.occupied_space_in_bytes =
            bins.decrypted_txs.allotted_space_in_bytes;

        // make sure we can't dump any new decrypted txs in the bin
        assert_matches!(
            bins.try_alloc(b"arbitrary tx bytes"),
            AllocStatus::Rejected { .. }
        );
    }

    /// Implementation of [`test_bin_capacity_eq_provided_space`].
    fn proptest_bin_capacity_eq_provided_space(
        tendermint_max_block_space_in_bytes: u64,
    ) {
        let bins =
            BlockSpaceAllocator::init(tendermint_max_block_space_in_bytes);
        assert_eq!(0, bins.uninitialized_space_in_bytes());
    }

    /// Implementation of [`test_tx_dump_doesnt_fill_up_bin`].
    fn proptest_tx_dump_doesnt_fill_up_bin(args: PropTx) {
        let PropTx {
            tendermint_max_block_space_in_bytes,
            protocol_txs,
            encrypted_txs,
            decrypted_txs,
        } = args;

        // produce new txs until the moment we would have
        // filled up the bins.
        //
        // iterate over the produced txs to make sure we can keep
        // dumping new txs without filling up the bins

        let bins = RefCell::new(BlockSpaceAllocator::init(
            tendermint_max_block_space_in_bytes,
        ));
        let decrypted_txs = decrypted_txs.into_iter().take_while(|tx| {
            let bin = bins.borrow().decrypted_txs;
            let new_size = bin.occupied_space_in_bytes + tx.len() as u64;
            new_size < bin.allotted_space_in_bytes
        });
        for tx in decrypted_txs {
            assert_matches!(
                bins.borrow_mut().try_alloc(&tx),
                AllocStatus::Accepted
            );
        }

        let bins = RefCell::new(bins.into_inner().next_state());
        let protocol_txs = protocol_txs.into_iter().take_while(|tx| {
            let bin = bins.borrow().protocol_txs;
            let new_size = bin.occupied_space_in_bytes + tx.len() as u64;
            new_size < bin.allotted_space_in_bytes
        });
        for tx in protocol_txs {
            assert_matches!(
                bins.borrow_mut().try_alloc(&tx),
                AllocStatus::Accepted
            );
        }

        let bins =
            RefCell::new(bins.into_inner().next_state_with_encrypted_txs());
        let encrypted_txs = encrypted_txs.into_iter().take_while(|tx| {
            let bin = bins.borrow().encrypted_txs;
            let new_size = bin.occupied_space_in_bytes + tx.len() as u64;
            new_size < bin.allotted_space_in_bytes
        });
        for tx in encrypted_txs {
            assert_matches!(
                bins.borrow_mut().try_alloc(&tx),
                AllocStatus::Accepted
            );
        }
    }

    prop_compose! {
        /// Generate arbitrarily sized txs of different kinds.
        fn arb_transactions()
            // create base strategies
            (
                (tendermint_max_block_space_in_bytes, protocol_tx_max_bin_size, encrypted_tx_max_bin_size,
                 decrypted_tx_max_bin_size) in arb_max_bin_sizes(),
            )
            // compose strategies
            (
                tendermint_max_block_space_in_bytes in Just(tendermint_max_block_space_in_bytes),
                protocol_txs in arb_tx_list(protocol_tx_max_bin_size),
                encrypted_txs in arb_tx_list(encrypted_tx_max_bin_size),
                decrypted_txs in arb_tx_list(decrypted_tx_max_bin_size),
            )
            -> PropTx {
                PropTx {
                    tendermint_max_block_space_in_bytes,
                    protocol_txs,
                    encrypted_txs,
                    decrypted_txs,
                }
            }
    }

    /// Return random bin sizes for a [`BlockSpaceAllocator`].
    fn arb_max_bin_sizes() -> impl Strategy<Value = (u64, usize, usize, usize)>
    {
        const MAX_BLOCK_SIZE_BYTES: u64 = 1000;
        (1..=MAX_BLOCK_SIZE_BYTES).prop_map(
            |tendermint_max_block_space_in_bytes| {
                (
                    tendermint_max_block_space_in_bytes,
                    (thres::ONE_THIRD * tendermint_max_block_space_in_bytes)
                        .to_integer() as usize,
                    (thres::ONE_THIRD * tendermint_max_block_space_in_bytes)
                        .to_integer() as usize,
                    (thres::ONE_THIRD * tendermint_max_block_space_in_bytes)
                        .to_integer() as usize,
                )
            },
        )
    }

    /// Return a list of txs.
    fn arb_tx_list(max_bin_size: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
        const MAX_TX_NUM: usize = 64;
        let tx = prop::collection::vec(prop::num::u8::ANY, 0..=max_bin_size);
        prop::collection::vec(tx, 0..=MAX_TX_NUM)
    }
}
