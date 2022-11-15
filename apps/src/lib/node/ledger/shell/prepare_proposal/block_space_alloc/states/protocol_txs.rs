use super::super::{AllocStatus, BlockSpaceAllocator};
use super::{
    BuildingEncryptedTxBatch, BuildingProtocolTxBatch, State, WithEncryptedTxs,
    WithoutEncryptedTxs,
};

impl State<WithEncryptedTxs> for BlockSpaceAllocator<BuildingProtocolTxBatch> {
    type Next = BlockSpaceAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>>;

    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        self.protocol_txs.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.protocol_txs.try_dump_all(txs)
    }

    #[inline]
    fn next_state(self) -> Self::Next {
        todo!()
    }
}

impl State<WithoutEncryptedTxs>
    for BlockSpaceAllocator<BuildingProtocolTxBatch>
{
    type Next =
        BlockSpaceAllocator<BuildingEncryptedTxBatch<WithoutEncryptedTxs>>;

    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        self.protocol_txs.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.protocol_txs.try_dump_all(txs)
    }

    #[inline]
    fn next_state(self) -> Self::Next {
        todo!()
    }
}
