//! Primitives that facilitate keeping track of the number
//! of bytes utilized by the current consensus round's proposal.
//!
//! This is important, because Tendermint places an upper bound
//! on the size of a block.

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

impl TxAllotedSpace {
    /// Construct a new [`TxAllotedSpace`], with an upper bound
    /// on the max number of txs in a block defined by Tendermint.
    #[allow(dead_code)]
    #[inline]
    pub fn init_from(req: &RequestPrepareProposal) -> Self {
        // each tx bin gets 1/3 of the alloted space
        const THRES: f64 = 1.0 / 3.0;
        let max = req.max_tx_bytes as u64;
        Self {
            provided_by_tendermint: max,
            protocol_txs: TxBin::init_from(max, THRES),
            encrypted_txs: TxBin::init_from(max, THRES),
            decrypted_txs: TxBin::init_from(max, THRES),
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
    /// of txs defined by a ratio over Tendermint's own max.
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
