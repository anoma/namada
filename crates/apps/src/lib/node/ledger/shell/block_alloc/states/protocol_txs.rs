use std::marker::PhantomData;

use super::super::{AllocFailure, BlockAllocator};
use super::{
    BuildingProtocolTxBatch, BuildingTxBatch, NextStateImpl, TryAlloc,
    WithNormalTxs,
};
use crate::node::ledger::shell::block_alloc::TxBin;

impl<T> TryAlloc for BlockAllocator<BuildingProtocolTxBatch<T>> {
    type Resources<'tx> = &'tx [u8];

    #[inline]
    fn try_alloc(
        &mut self,
        tx: Self::Resources<'_>,
    ) -> Result<(), AllocFailure> {
        self.protocol_txs.try_dump(tx)
    }
}

impl NextStateImpl for BlockAllocator<BuildingProtocolTxBatch<WithNormalTxs>> {
    type Next = BlockAllocator<BuildingTxBatch>;

    #[inline]
    fn next_state_impl(mut self) -> Self::Next {
        self.protocol_txs.shrink_to_fit();
        let remaining_free_space = self.uninitialized_space_in_bytes();
        self.normal_txs.space = TxBin::init(remaining_free_space);
        // cast state
        let BlockAllocator {
            block,
            protocol_txs,
            normal_txs,
            ..
        } = self;

        BlockAllocator {
            _state: PhantomData,
            block,
            protocol_txs,
            normal_txs,
        }
    }
}
