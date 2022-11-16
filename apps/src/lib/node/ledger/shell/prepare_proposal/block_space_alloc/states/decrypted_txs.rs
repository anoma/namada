use std::marker::PhantomData;

use super::super::{thres, AllocStatus, BlockSpaceAllocator, TxBin};
use super::{
    BuildingDecryptedTxBatch, BuildingProtocolTxBatch, NextStateImpl, State,
};

impl State for BlockSpaceAllocator<BuildingDecryptedTxBatch> {
    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        self.decrypted_txs.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.decrypted_txs.try_dump_all(txs)
    }
}

impl NextStateImpl for BlockSpaceAllocator<BuildingDecryptedTxBatch> {
    type Next = BlockSpaceAllocator<BuildingProtocolTxBatch>;

    #[inline]
    fn next_state_impl(mut self) -> Self::Next {
        self.decrypted_txs.shrink();

        // reserve space for protocol txs
        let uninit = self.uninitialized_space_in_bytes();
        self.protocol_txs = TxBin::init_over_ratio(uninit, thres::ONE_THIRD);

        // cast state
        let Self {
            block,
            protocol_txs,
            encrypted_txs,
            decrypted_txs,
            ..
        } = self;

        BlockSpaceAllocator {
            _state: PhantomData,
            block,
            protocol_txs,
            encrypted_txs,
            decrypted_txs,
        }
    }
}
