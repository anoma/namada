use std::marker::PhantomData;

use super::super::{thres, AllocStatus, BlockSpaceAllocator, TxBin};
use super::{
    BuildingDecryptedTxBatch, BuildingProtocolTxBatch, NextStateImpl, State,
};

impl State for BlockSpaceAllocator<BuildingDecryptedTxBatch> {
    #[inline]
    fn try_alloc<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
        self.decrypted_txs.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus<'tx>
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
        let remaining_free_space = self.uninitialized_space_in_bytes();
        self.protocol_txs =
            TxBin::init_over_ratio(remaining_free_space, thres::ONE_THIRD);

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
