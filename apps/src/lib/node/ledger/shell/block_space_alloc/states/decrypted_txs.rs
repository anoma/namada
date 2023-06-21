use std::marker::PhantomData;

use super::super::{AllocFailure, BlockSpaceAllocator, DumpResource, TxBin};
use super::{
    BuildingDecryptedTxBatch, BuildingProtocolTxBatch, NextStateImpl, TryAlloc,
};

impl TryAlloc for BlockSpaceAllocator<BuildingDecryptedTxBatch> {
    type Resource<'tx> = &'tx [u8];

    #[inline]
    fn try_alloc<'tx>(
        &mut self,
        tx: Self::Resource<'tx>,
    ) -> Result<(), AllocFailure> {
        self.decrypted_txs.try_dump(DumpResource::Space(tx))
    }
}

impl NextStateImpl for BlockSpaceAllocator<BuildingDecryptedTxBatch> {
    type Next = BlockSpaceAllocator<BuildingProtocolTxBatch>;

    #[inline]
    fn next_state_impl(mut self) -> Self::Next {
        self.decrypted_txs.shrink_to_fit();

        // the remaining space is allocated to protocol txs
        let remaining_free_space = self.uninitialized_space_in_bytes();
        self.protocol_txs = TxBin::init(remaining_free_space);

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
