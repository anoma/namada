use super::super::{AllocFailure, BlockSpaceAllocator};
use super::{BuildingProtocolTxBatch, TryAlloc};

impl TryAlloc for BlockSpaceAllocator<BuildingProtocolTxBatch> {
    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> Result<(), AllocFailure> {
        self.protocol_txs.try_dump(tx)
    }
}
