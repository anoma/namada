use super::super::{AllocFailure, BlockSpaceAllocator, DumpResource};
use super::{BuildingProtocolTxBatch, TryAlloc};

impl TryAlloc for BlockSpaceAllocator<BuildingProtocolTxBatch> {
    type Resource<'tx> = &'tx [u8];

    #[inline]
    fn try_alloc<'tx>(
        &mut self,
        tx: Self::Resource<'tx>,
    ) -> Result<(), AllocFailure> {
        self.protocol_txs.try_dump(DumpResource::Space(tx))
    }
}
