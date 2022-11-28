use std::marker::PhantomData;

use super::super::{AllocFailure, BlockSpaceAllocator};
use super::{
    BuildingEncryptedTxBatch, FillingRemainingSpace, NextStateImpl, TryAlloc,
    WithEncryptedTxs, WithoutEncryptedTxs,
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
    fn try_alloc(&mut self, _tx: &[u8]) -> Result<(), AllocFailure> {
        Err(AllocFailure::Rejected { bin_space_left: 0 })
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
