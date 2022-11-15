use std::marker::PhantomData;

use super::super::{AllocStatus, BlockSpaceAllocator};
use super::{
    BuildingEncryptedTxBatch, FillingRemainingSpace, State, WithEncryptedTxs,
    WithoutEncryptedTxs,
};

impl State for BlockSpaceAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>> {
    type Next = BlockSpaceAllocator<FillingRemainingSpace<WithEncryptedTxs>>;

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
        next_state(self)
    }
}

impl State
    for BlockSpaceAllocator<BuildingEncryptedTxBatch<WithoutEncryptedTxs>>
{
    type Next = BlockSpaceAllocator<FillingRemainingSpace<WithoutEncryptedTxs>>;

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
