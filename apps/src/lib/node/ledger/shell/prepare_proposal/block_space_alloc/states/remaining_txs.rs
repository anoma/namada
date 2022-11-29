use super::super::{AllocFailure, BlockSpaceAllocator};
use super::{FillingRemainingSpace, TryAlloc};

impl TryAlloc for BlockSpaceAllocator<FillingRemainingSpace> {
    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> Result<(), AllocFailure> {
        // NOTE: tx dispatching is done at at higher level, to prevent
        // allocating space for encrypted txs here
        self.block.try_dump(tx)
    }
}
