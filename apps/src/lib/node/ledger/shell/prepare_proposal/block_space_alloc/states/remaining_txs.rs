use super::super::{AllocStatus, BlockSpaceAllocator};
use super::{
    FillingRemainingSpace, State, WithEncryptedTxs, WithoutEncryptedTxs,
};

impl State for BlockSpaceAllocator<FillingRemainingSpace<WithEncryptedTxs>> {
    type Next = ();

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

    #[inline]
    fn next_state(self) -> Self::Next {
        // NOOP
    }
}

impl State for BlockSpaceAllocator<FillingRemainingSpace<WithoutEncryptedTxs>> {
    type Next = ();

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

    #[inline]
    fn next_state(self) -> Self::Next {
        // NOOP
    }
}
