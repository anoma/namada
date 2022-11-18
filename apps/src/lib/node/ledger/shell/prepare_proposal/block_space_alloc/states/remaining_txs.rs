use itertools::Either::*;

use super::super::{AllocStatus, BlockSpaceAllocator};
use super::{
    FillingRemainingSpace, RemainingBatchAllocator, TryAlloc, WithEncryptedTxs,
    WithoutEncryptedTxs,
};

impl TryAlloc for BlockSpaceAllocator<FillingRemainingSpace<WithEncryptedTxs>> {
    #[inline]
    fn try_alloc<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
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
    fn try_alloc<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
        self.block.try_dump(tx)
    }
}

impl TryAlloc for RemainingBatchAllocator {
    #[inline]
    fn try_alloc<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
        match self {
            Left(state) => state.try_alloc(tx),
            Right(state) => state.try_alloc(tx),
        }
    }
}
