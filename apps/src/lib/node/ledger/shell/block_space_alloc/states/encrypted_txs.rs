use std::marker::PhantomData;

use super::super::{AllocFailure, BlockSpaceAllocator, TxBin};
use super::{
    BuildingDecryptedTxBatch, BuildingEncryptedTxBatch,
    EncryptedTxBatchAllocator, NextStateImpl, TryAlloc, WithEncryptedTxs,
    WithoutEncryptedTxs,
};

impl TryAlloc
    for BlockSpaceAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>>
{
    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> Result<(), AllocFailure> {
        self.encrypted_txs.try_dump(tx)
    }
}

impl NextStateImpl
    for BlockSpaceAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>>
{
    type Next = BlockSpaceAllocator<BuildingDecryptedTxBatch>;

    #[inline]
    fn next_state_impl(self) -> Self::Next {
        next_state(self)
    }
}

impl TryAlloc
    for BlockSpaceAllocator<BuildingEncryptedTxBatch<WithoutEncryptedTxs>>
{
    #[inline]
    fn try_alloc(&mut self, _tx: &[u8]) -> Result<(), AllocFailure> {
        Err(AllocFailure::Rejected { bin_space_left: 0 })
    }
}

impl NextStateImpl
    for BlockSpaceAllocator<BuildingEncryptedTxBatch<WithoutEncryptedTxs>>
{
    type Next = BlockSpaceAllocator<BuildingDecryptedTxBatch>;

    #[inline]
    fn next_state_impl(self) -> Self::Next {
        next_state(self)
    }
}

#[inline]
fn next_state<Mode>(
    mut alloc: BlockSpaceAllocator<BuildingEncryptedTxBatch<Mode>>,
) -> BlockSpaceAllocator<BuildingDecryptedTxBatch> {
    alloc.encrypted_txs.shrink_to_fit();

    // decrypted txs can use as much space as they need - which
    // in practice will only be, at most, 1/3 of the block space
    // used by encrypted txs at the prev height
    let remaining_free_space = alloc.uninitialized_space_in_bytes();
    alloc.protocol_txs = TxBin::init(remaining_free_space);

    // cast state
    let BlockSpaceAllocator {
        block,
        protocol_txs,
        encrypted_txs,
        decrypted_txs,
        ..
    } = alloc;

    BlockSpaceAllocator {
        _state: PhantomData,
        block,
        protocol_txs,
        encrypted_txs,
        decrypted_txs,
    }
}

impl TryAlloc for EncryptedTxBatchAllocator {
    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> Result<(), AllocFailure> {
        match self {
            EncryptedTxBatchAllocator::WithEncryptedTxs(state) => {
                state.try_alloc(tx)
            }
            EncryptedTxBatchAllocator::WithoutEncryptedTxs(state) => {
                // NOTE: this operation will cause the allocator to
                // run out of memory immediately
                state.try_alloc(tx)
            }
        }
    }
}

impl NextStateImpl for EncryptedTxBatchAllocator {
    type Next = BlockSpaceAllocator<BuildingDecryptedTxBatch>;

    #[inline]
    fn next_state_impl(self) -> Self::Next {
        match self {
            EncryptedTxBatchAllocator::WithEncryptedTxs(state) => {
                state.next_state_impl()
            }
            EncryptedTxBatchAllocator::WithoutEncryptedTxs(state) => {
                state.next_state_impl()
            }
        }
    }
}
