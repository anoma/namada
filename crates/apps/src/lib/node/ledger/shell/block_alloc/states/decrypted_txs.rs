use std::marker::PhantomData;

use super::super::{AllocFailure, BlockAllocator, TxBin};
use super::{
    BuildingDecryptedTxBatch, BuildingProtocolTxBatch, NextStateImpl, TryAlloc,
};

impl TryAlloc for BlockAllocator<BuildingDecryptedTxBatch> {
    type Resources<'tx> = &'tx [u8];

    #[inline]
    fn try_alloc(
        &mut self,
        tx: Self::Resources<'_>,
    ) -> Result<(), AllocFailure> {
        self.decrypted_txs.try_dump(tx)
    }
}

impl NextStateImpl for BlockAllocator<BuildingDecryptedTxBatch> {
    type Next = BlockAllocator<BuildingProtocolTxBatch>;

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

        BlockAllocator {
            _state: PhantomData,
            block,
            protocol_txs,
            encrypted_txs,
            decrypted_txs,
        }
    }
}
