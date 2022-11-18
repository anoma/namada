use std::marker::PhantomData;

use super::super::{AllocStatus, BlockSpaceAllocator};
use super::{
    BuildingEncryptedTxBatch, FillingRemainingSpace, NextStateImpl, State,
    WithEncryptedTxs, WithoutEncryptedTxs,
};

impl State for BlockSpaceAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>> {
    #[inline]
    fn try_alloc<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
        self.encrypted_txs.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus<'tx>
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.encrypted_txs.try_dump_all(txs)
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

impl State
    for BlockSpaceAllocator<BuildingEncryptedTxBatch<WithoutEncryptedTxs>>
{
    #[inline]
    fn try_alloc<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
        AllocStatus::Rejected { tx, space_left: 0 }
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus<'tx>
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        let tx = txs
            .into_iter()
            .next()
            .expect("We should have had at least one tx in the batch");
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
    alloc.encrypted_txs.shrink();

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
