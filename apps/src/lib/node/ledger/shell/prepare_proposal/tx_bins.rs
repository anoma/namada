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
        Self {
            provided_by_tendermint: max,
            protocol_txs: TxBin::init_from(max, thres::PROTOCOL_TX),
            encrypted_txs: TxBin::init_from(max, thres::ENCRYPTED_TX),
            decrypted_txs: TxBin::init_from(max, thres::DECRYPTED_TX),
        }
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
    fn init_from(tendermint_max_block_space: u64, frac: f64) -> Self {
        let alloted_space = (tendermint_max_block_space as f64 * frac) as u64;
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

    /// The threshold over Tendermint's alloted space for protocol txs.
    pub const PROTOCOL_TX: f64 = 1.0 / 3.0;

    /// The threshold over Tendermint's alloted space for DKG encrypted txs.
    pub const ENCRYPTED_TX: f64 = 1.0 / 3.0;

    /// The threshold over Tendermint's alloted space for DKG decrypted txs.
    pub const DECRYPTED_TX: f64 = 1.0 / 3.0;
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
        assert!(sum <= 1.0)
    }

    /// Implementation of [`test_bin_capacity_eq_provided_space`].
    fn proptest_bin_capacity_eq_provided_space(
        tendermint_max_block_space: u64,
    ) {
        let bins = TxAllotedSpace::init(tendermint_max_block_space);
        let total_bin_space = bins.protocol_txs.alloted_space
            + bins.encrypted_txs.alloted_space
            + bins.decrypted_txs.alloted_space;
        assert_eq!(bins.provided_by_tendermint, total_bin_space);
    }

    proptest! {
        /// Check if the sum of all individual bin allotments for a
        /// [`TxAllotedSpace`] corresponds to the total space ceded
        /// by Tendermint.
        #[test]
        fn test_bin_capacity_eq_provided_space(max in 0..u64::MAX) {
            proptest_bin_capacity_eq_provided_space(max)
        }
    }
}
