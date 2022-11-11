//! Primitives that facilitate keeping track of the number
//! of bytes utilized by some Tendermint consensus round's proposal.
//!
//! This is important, because Tendermint places an upper bound
//! on the size of a block, rejecting blocks whose size exceeds
//! the limit stated in [`RequestPrepareProposal`].
//!
//! In the current implementation, each kind of transaction in
//! Namada gets a portion of (i.e. threshold over) the total
//! alloted space.

// TODO: what if a tx has a size greater than the threshold for
// its bin? how do we handle this? if we keep it in the mempool
// forever, it'll be a DoS vec, as we can make nodes run out of
// memory! maybe we should allow block decisions for txs that are
// too big to fit in their respective bin? in these special block
// decisions, we would only decide proposals with "large" txs

// TODO: refactor our measure of space to also reflect gas costs.
// the total gas of all chosen txs cannot exceed the configured max
// gas per block, otherwise a proposal will be rejected!

use num_rational::Ratio;

use crate::facade::tendermint_proto::abci::RequestPrepareProposal;

/// Alloted space for a batch of transactions in some proposed block,
/// measured in bytes.
///
/// We keep track of the current space utilized by:
///
///   - Protocol transactions.
///   - DKG decrypted transactions.
///   - DKG encrypted transactions.
#[derive(Default)]
#[allow(dead_code)]
pub struct TxAllotedSpace {
    /// The total space Tendermint has allotted to the
    /// application for the current block height.
    provided_by_tendermint: u64,
    /// The current space utilized by protocol transactions.
    protocol_txs: TxBin,
    /// The current space utilized by DKG encrypted transactions.
    encrypted_txs: TxBin,
    /// The current space utilized by DKG decrypted transactions.
    decrypted_txs: TxBin,
}

impl From<&RequestPrepareProposal> for TxAllotedSpace {
    #[inline]
    fn from(req: &RequestPrepareProposal) -> Self {
        let tendermint_max_block_space = req.max_tx_bytes as u64;
        Self::init(tendermint_max_block_space)
    }
}

impl TxAllotedSpace {
    /// Construct a new [`TxAllotedSpace`], with an upper bound
    /// on the max number of txs in a block defined by Tendermint.
    #[allow(dead_code)]
    #[inline]
    pub fn init(tendermint_max_block_space: u64) -> Self {
        let max = tendermint_max_block_space;
        let mut bins = Self {
            provided_by_tendermint: max,
            protocol_txs: TxBin::init_from(max, thres::PROTOCOL_TX),
            encrypted_txs: TxBin::init_from(max, thres::ENCRYPTED_TX),
            decrypted_txs: TxBin::init_from(max, thres::DECRYPTED_TX),
        };
        // concede leftover space to protocol txs
        bins.protocol_txs.alloted_space += bins.leftover_space();
        bins
    }

    /// Return leftover space in bins, resulting from ratio conversions.
    fn leftover_space(&self) -> u64 {
        let total_bin_space = self.protocol_txs.alloted_space
            + self.encrypted_txs.alloted_space
            + self.decrypted_txs.alloted_space;
        self.provided_by_tendermint - total_bin_space
    }

    /// Try to allocate space for a new protocol transaction.
    #[allow(dead_code)]
    #[inline]
    pub fn try_alloc_protocol_tx(&mut self, tx: &[u8]) -> bool {
        self.protocol_txs.try_dump(tx)
    }

    /// Try to allocate space for a new DKG encrypted transaction.
    #[allow(dead_code)]
    #[inline]
    pub fn try_alloc_encrypted_tx(&mut self, tx: &[u8]) -> bool {
        self.encrypted_txs.try_dump(tx)
    }

    /// Try to allocate space for a new DKG decrypted transaction.
    #[allow(dead_code)]
    #[inline]
    pub fn try_alloc_decrypted_tx(&mut self, tx: &[u8]) -> bool {
        self.decrypted_txs.try_dump(tx)
    }

    /// The total space, in bytes, occupied by each transaction.
    #[allow(dead_code)]
    #[inline]
    pub fn occupied_space(&self) -> u64 {
        self.protocol_txs.current_space
            + self.encrypted_txs.current_space
            + self.decrypted_txs.current_space
    }

    /// Return the amount, in bytes, of free space in this
    /// [`TxAllotedSpace`].
    #[allow(dead_code)]
    #[inline]
    pub fn free_space(&self) -> u64 {
        self.provided_by_tendermint - self.occupied_space()
    }

    /// Checks if this [`TxAllotedSpace`] has any free space remaining.
    #[allow(dead_code)]
    #[inline]
    pub fn has_free_space(&self) -> bool {
        self.free_space() > 0
    }
}

/// Alloted space for a batch of transactions of the same kind in some
/// proposed block, measured in bytes.
#[derive(Default)]
#[allow(dead_code)]
struct TxBin {
    /// The current space utilized by the batch of transactions.
    current_space: u64,
    /// The maximum space the batch of transactions may occupy.
    alloted_space: u64,
}

impl TxBin {
    /// Construct a new [`TxBin`], with an upper bound on the max number
    /// of storable txs defined by a ratio over Tendermint max block size.
    #[allow(dead_code)]
    #[inline]
    fn init_from(tendermint_max_block_space: u64, frac: Ratio<u64>) -> Self {
        let alloted_space = (frac * tendermint_max_block_space).to_integer();
        Self {
            alloted_space,
            current_space: 0,
        }
    }

    /// Try to dump a new transaction into this [`TxBin`].
    #[allow(dead_code)]
    #[inline]
    fn try_dump(&mut self, tx: &[u8]) -> bool {
        let new_space = self.current_space + tx.len() as u64;
        if new_space > self.alloted_space {
            self.current_space = new_space;
            true
        } else {
            false
        }
    }
}

mod thres {
    //! Transaction allotment thresholds.

    use num_rational::Ratio;

    /// The threshold over Tendermint's alloted space for protocol txs.
    pub const PROTOCOL_TX: Ratio<u64> = Ratio::new_raw(1, 3);

    /// The threshold over Tendermint's alloted space for DKG encrypted txs.
    pub const ENCRYPTED_TX: Ratio<u64> = Ratio::new_raw(1, 3);

    /// The threshold over Tendermint's alloted space for DKG decrypted txs.
    pub const DECRYPTED_TX: Ratio<u64> = Ratio::new_raw(1, 3);
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Check if the sum of all individual tx thresholds does
    /// not exceed one.
    ///
    /// This is important, because we do not want to exceed
    /// the maximum block size in Tendermint, and get randomly
    /// rejected blocks.
    #[test]
    fn test_tx_thres_doesnt_exceed_one() {
        let sum =
            thres::PROTOCOL_TX + thres::ENCRYPTED_TX + thres::DECRYPTED_TX;
        assert_eq!(sum.to_integer(), 1);
    }

    /// Implementation of [`test_bin_capacity_eq_provided_space`].
    fn proptest_bin_capacity_eq_provided_space(
        tendermint_max_block_space: u64,
    ) {
        let bins = TxAllotedSpace::init(tendermint_max_block_space);
        assert_eq!(0, bins.leftover_space());
    }

    proptest! {
        /// Check if the sum of all individual bin allotments for a
        /// [`TxAllotedSpace`] corresponds to the total space ceded
        /// by Tendermint.
        #[test]
        fn test_bin_capacity_eq_provided_space(max in prop::num::u64::ANY) {
            proptest_bin_capacity_eq_provided_space(max)
        }
    }

    prop_compose! {
        /// Generate arbitrarily sized txs of different kinds.
        fn arb_transactions_with_min_block_space()
            // create base strategies
            (
                (tendermint_max_block_space, protocol_tx_max_bin_size, encrypted_tx_max_bin_size,
                 decrypted_tx_max_bin_size) in arb_max_bin_sizes(),
            )
            // compose strategies
            (
                tendermint_max_block_space in Just(tendermint_max_block_space),
                protocol_txs in prop::collection::vec(prop::num::u8::ANY, 0..=protocol_tx_max_bin_size),
                encrypted_txs in prop::collection::vec(prop::num::u8::ANY, 0..=encrypted_tx_max_bin_size),
                decrypted_txs in prop::collection::vec(prop::num::u8::ANY, 0..=decrypted_tx_max_bin_size),
            )
            -> (u64, Vec<u8>, Vec<u8>, Vec<u8>) {
                (tendermint_max_block_space, protocol_txs, encrypted_txs, decrypted_txs)
            }
    }

    /// Return random bin sizes for a [`TxAllotedSpace`].
    #[allow(dead_code)]
    fn arb_max_bin_sizes() -> impl Strategy<Value = (u64, usize, usize, usize)>
    {
        (1..=u64::MAX).prop_map(|tendermint_max_block_space| {
            (
                tendermint_max_block_space,
                (thres::PROTOCOL_TX * tendermint_max_block_space).to_integer()
                    as usize,
                (thres::ENCRYPTED_TX * tendermint_max_block_space).to_integer()
                    as usize,
                (thres::DECRYPTED_TX * tendermint_max_block_space).to_integer()
                    as usize,
            )
        })
    }
}
