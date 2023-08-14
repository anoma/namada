use super::super::{AllocFailure, BlockAllocator};
use super::{BuildingProtocolTxBatch, TryAlloc};

impl TryAlloc for BlockAllocator<BuildingProtocolTxBatch> {
    type Resource<'tx> = &'tx [u8];

    #[inline]
    fn try_alloc(
        &mut self,
        tx: Self::Resource<'_>,
    ) -> Result<(), AllocFailure> {
        self.protocol_txs.try_dump(tx)
    }
}
