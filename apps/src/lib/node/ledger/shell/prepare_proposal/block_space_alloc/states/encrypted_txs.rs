use std::marker::PhantomData;

use super::super::{AllocStatus, BlockSpaceAllocator};
use super::{
    BuildingEncryptedTxBatch, EncryptedTxBatchAllocator, FillingRemainingSpace,
    NextStateImpl, RemainingBatchAllocator, TryAlloc, WithEncryptedTxs,
    WithoutEncryptedTxs,
};

impl TryAlloc
    for BlockSpaceAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>>
{
    #[inline]
    fn try_alloc<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
        self.encrypted_txs.try_dump(tx)
    }
}

impl NextStateImpl
    for BlockSpaceAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>>
{
    type Next = BlockSpaceAllocator<FillingRemainingSpace<WithEncryptedTxs>>;

    #[inline]
    fn next_state_impl(self) -> Self::Next {
        next_state(self)
    }
}

impl TryAlloc
    for BlockSpaceAllocator<BuildingEncryptedTxBatch<WithoutEncryptedTxs>>
{
    #[inline]
    fn try_alloc<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
        AllocStatus::Rejected { tx, space_left: 0 }
    }
}

impl NextStateImpl
    for BlockSpaceAllocator<BuildingEncryptedTxBatch<WithoutEncryptedTxs>>
{
    type Next = BlockSpaceAllocator<FillingRemainingSpace<WithoutEncryptedTxs>>;

    #[inline]
    fn next_state_impl(self) -> Self::Next {
        next_state(self)
    }
}

#[inline]
fn next_state<Mode>(
    mut alloc: BlockSpaceAllocator<BuildingEncryptedTxBatch<Mode>>,
) -> BlockSpaceAllocator<FillingRemainingSpace<Mode>> {
    alloc.encrypted_txs.shrink_to_fit();

    // reserve space for any remaining txs
    alloc.claim_block_space();

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
    fn try_alloc<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
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
    type Next = RemainingBatchAllocator;

    #[inline]
    fn next_state_impl(self) -> Self::Next {
        match self {
            EncryptedTxBatchAllocator::WithEncryptedTxs(state) => {
                RemainingBatchAllocator::WithEncryptedTxs(
                    state.next_state_impl(),
                )
            }
            EncryptedTxBatchAllocator::WithoutEncryptedTxs(state) => {
                RemainingBatchAllocator::WithoutEncryptedTxs(
                    state.next_state_impl(),
                )
            }
        }
    }
}
