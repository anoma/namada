use super::super::{AllocStatus, BlockSpaceAllocator};
use super::{
    FillingRemainingSpace, State, WithEncryptedTxs, WithoutEncryptedTxs,
};

impl State for BlockSpaceAllocator<FillingRemainingSpace<WithEncryptedTxs>> {
    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        self.block.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.block.try_dump_all(txs)
    }
}

// TODO: limit txs that can go in the bins at this level? so we don't misuse
// the abstraction. it's not like we can't push encrypted txs into the bins,
// right now...
impl State for BlockSpaceAllocator<FillingRemainingSpace<WithoutEncryptedTxs>> {
    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        self.block.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.block.try_dump_all(txs)
    }
}
