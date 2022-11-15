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
#[derive(Debug, Default)]
pub struct BlockSpaceAllocator<State> {
    /// The current state of the [`BlockSpaceAllocator`] state machine.
    _state: PhantomData<*const State>,
    /// The total space Tendermint has allotted to the
    /// application for the current block height.
    max_block_space_in_bytes: u64,
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
            max_block_space_in_bytes: max,
            protocol_txs: TxBin::default(),
            encrypted_txs: TxBin::default(),
            // decrypted txs can use as much space as needed; in practice,
            // we'll only need, at most, the amount of space reserved for
            // encrypted txs at the prev block height
            decrypted_txs: TxBin::init(max),
        }
    }
}

impl states::State for BlockSpaceAllocator<states::BuildingDecryptedTxBatch> {
    type Next = BlockSpaceAllocator<states::BuildingProtocolTxBatch>;

    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        self.decrypted_txs.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.decrypted_txs.try_dump_all(txs)
    }

    #[inline]
    fn next_state(mut self) -> Self::Next {
        // seal decrypted txs
        self.decrypted_txs.allotted_space_in_bytes =
            self.decrypted_txs.current_space_in_bytes;

        // reserve space for protocol txs
        let uninit = self.uninitialized_space_in_bytes();
        self.protocol_txs = TxBin::init_over_ratio(uninit, thres::ONE_THIRD);

        // cast state
        let Self {
            max_block_space_in_bytes,
            protocol_txs,
            encrypted_txs,
            decrypted_txs,
            ..
        } = self;

        BlockSpaceAllocator {
            _state: PhantomData,
            max_block_space_in_bytes,
            protocol_txs,
            encrypted_txs,
            decrypted_txs,
        }
    }
}

impl states::State<states::WithEncryptedTxs>
    for BlockSpaceAllocator<states::BuildingProtocolTxBatch>
{
    type Next = BlockSpaceAllocator<
        states::BuildingEncryptedTxBatch<states::WithEncryptedTxs>,
    >;

    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        self.protocol_txs.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.protocol_txs.try_dump_all(txs)
    }

    #[inline]
    fn next_state(self) -> Self::Next {
        todo!()
    }
}

impl states::State<states::WithoutEncryptedTxs>
    for BlockSpaceAllocator<states::BuildingProtocolTxBatch>
{
    type Next = BlockSpaceAllocator<
        states::BuildingEncryptedTxBatch<states::WithoutEncryptedTxs>,
    >;

    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        self.protocol_txs.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.protocol_txs.try_dump_all(txs)
    }

    #[inline]
    fn next_state(self) -> Self::Next {
        todo!()
    }
}

impl states::State
    for BlockSpaceAllocator<
        states::BuildingEncryptedTxBatch<states::WithEncryptedTxs>,
    >
{
    type Next = BlockSpaceAllocator<
        states::FillingRemainingSpace<states::WithEncryptedTxs>,
    >;

    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        self.encrypted_txs.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.encrypted_txs.try_dump_all(txs)
    }

    #[inline]
    fn next_state(self) -> Self::Next {
        todo!()
    }
}

impl states::State
    for BlockSpaceAllocator<
        states::BuildingEncryptedTxBatch<states::WithoutEncryptedTxs>,
    >
{
    type Next = BlockSpaceAllocator<
        states::FillingRemainingSpace<states::WithoutEncryptedTxs>,
    >;

    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        self.encrypted_txs.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.encrypted_txs.try_dump_all(txs)
    }

    #[inline]
    fn next_state(self) -> Self::Next {
        todo!()
    }
}

impl states::State
    for BlockSpaceAllocator<
        states::FillingRemainingSpace<states::WithEncryptedTxs>,
    >
{
    type Next = ();

    #[inline]
    fn try_alloc(&mut self, _tx: &[u8]) -> AllocStatus {
        todo!()
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, _txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        todo!()
    }

    #[inline]
    fn next_state(self) -> Self::Next {
        // NOOP
    }
}

impl states::State
    for BlockSpaceAllocator<
        states::FillingRemainingSpace<states::WithoutEncryptedTxs>,
    >
{
    type Next = ();

    #[inline]
    fn try_alloc(&mut self, _tx: &[u8]) -> AllocStatus {
        todo!()
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, _txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        todo!()
    }

    #[inline]
    fn next_state(self) -> Self::Next {
        // NOOP
    }
}

impl<State> BlockSpaceAllocator<State> {
    /// Return uninitialized space in tx bins, resulting from ratio conversions.
    ///
    /// This method should not be used outside of [`BlockSpaceAllocator`]
    /// instance construction or unit testing.
    #[allow(dead_code)]
    fn uninitialized_space_in_bytes(&self) -> u64 {
        let total_bin_space = self.protocol_txs.allotted_space_in_bytes
            + self.encrypted_txs.allotted_space_in_bytes
            + self.decrypted_txs.allotted_space_in_bytes;
        self.max_block_space_in_bytes - total_bin_space
    }

    /// The total space, in bytes, occupied by each transaction.
    #[inline]
    pub fn occupied_space_in_bytes(&self) -> u64 {
        self.protocol_txs.current_space_in_bytes
            + self.encrypted_txs.current_space_in_bytes
            + self.decrypted_txs.current_space_in_bytes
    }

    /// Return the amount, in bytes, of free space in this
    /// [`BlockSpaceAllocator`].
    #[inline]
    pub fn free_space_in_bytes(&self) -> u64 {
        self.max_block_space_in_bytes - self.occupied_space_in_bytes()
    }

    /// Checks if this [`BlockSpaceAllocator`] has any free space remaining.
    #[allow(dead_code)]
    #[inline]
    pub fn has_free_space(&self) -> bool {
        self.free_space_in_bytes() > 0
    }
}

/// Allotted space for a batch of transactions of the same kind in some
/// proposed block, measured in bytes.
#[derive(Debug, Copy, Clone, Default)]
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

    /// The threshold over Tendermint's allotted space for all three
    /// (major) kinds of Namada transations.
    pub const ONE_THIRD: Ratio<u64> = Ratio::new_raw(1, 3);
}
