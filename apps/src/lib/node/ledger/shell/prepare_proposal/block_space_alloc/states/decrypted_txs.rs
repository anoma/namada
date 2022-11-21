use std::marker::PhantomData;

use super::super::{threshold, AllocStatus, BlockSpaceAllocator, TxBin};
use super::{
    BuildingDecryptedTxBatch, BuildingProtocolTxBatch, NextStateImpl, TryAlloc,
};

impl TryAlloc for BlockSpaceAllocator<BuildingDecryptedTxBatch> {
    #[inline]
    fn try_alloc<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
        self.decrypted_txs.try_dump(tx)
    }
}

impl NextStateImpl for BlockSpaceAllocator<BuildingDecryptedTxBatch> {
    type Next = BlockSpaceAllocator<BuildingProtocolTxBatch>;

    #[inline]
    fn next_state_impl(mut self) -> Self::Next {
        self.decrypted_txs.shrink_to_fit();

        // reserve space for protocol txs
        self.protocol_txs = TxBin::init_over_ratio(
            self.block.allotted_space_in_bytes,
            threshold::ONE_THIRD,
        );

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
