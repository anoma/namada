use super::super::{AllocFailure, BlockAllocator};
use super::{BuildingProtocolTxBatch, TryAlloc};

impl TryAlloc for BlockAllocator<BuildingProtocolTxBatch> {
    type Resources<'tx> = &'tx [u8];

    #[inline]
    fn try_alloc(
        &mut self,
        tx: Self::Resources<'_>,
    ) -> Result<(), AllocFailure> {
        self.protocol_txs.try_dump(tx)
    }
}
