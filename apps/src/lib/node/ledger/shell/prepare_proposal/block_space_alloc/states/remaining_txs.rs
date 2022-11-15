use super::super::{AllocStatus, BlockSpaceAllocator};
use super::{
    FillingRemainingSpace, State, WithEncryptedTxs, WithoutEncryptedTxs,
};

impl State for BlockSpaceAllocator<FillingRemainingSpace<WithEncryptedTxs>> {
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

impl State for BlockSpaceAllocator<FillingRemainingSpace<WithoutEncryptedTxs>> {
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
