use super::super::{AllocFailure, BlockSpaceAllocator};
use super::{
    FillingRemainingSpace, TryAlloc, WithEncryptedTxs, WithoutEncryptedTxs,
};

impl TryAlloc for BlockSpaceAllocator<FillingRemainingSpace<WithEncryptedTxs>> {
    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> Result<(), AllocFailure> {
        self.block.try_dump(tx)
    }
}

// TODO: limit txs that can go in the bins at this level? so we don't misuse
// the abstraction. it's not like we can't push encrypted txs into the bins,
// right now...
impl TryAlloc
    for BlockSpaceAllocator<FillingRemainingSpace<WithoutEncryptedTxs>>
{
    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> Result<(), AllocFailure> {
        self.block.try_dump(tx)
    }
}
