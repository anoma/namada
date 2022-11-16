use std::marker::PhantomData;

use super::super::{AllocStatus, BlockSpaceAllocator};
use super::{
    BuildingEncryptedTxBatch, FillingRemainingSpace, NextStateImpl, State,
    WithEncryptedTxs, WithoutEncryptedTxs,
};

impl State for BlockSpaceAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>> {
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
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        AllocStatus::Rejected {
            tx_len: tx.len() as u64,
            space_left: 0,
        }
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, _txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        AllocStatus::Rejected {
            // arbitrary `tx_len` value; doesn't really matter what we
            // choose here, as long as it's greater than zero
            tx_len: u64::MAX,
            space_left: 0,
        }
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
