use std::marker::PhantomData;

use super::super::{AllocFailure, BlockAllocator, TxBin};
use super::{
    BuildingProtocolTxBatch, BuildingTxBatch, NextStateImpl, TryAlloc,
    WithoutNormalTxs,
};
use crate::node::ledger::shell::block_alloc::BlockResources;

impl TryAlloc for BlockAllocator<BuildingTxBatch> {
    type Resources<'tx> = BlockResources<'tx>;

    #[inline]
    fn try_alloc(
        &mut self,
        resource_required: Self::Resources<'_>,
    ) -> Result<(), AllocFailure> {
        self.normal_txs.space.try_dump(resource_required.tx)?;
        self.normal_txs.gas.try_dump(resource_required.gas)
    }
}

impl NextStateImpl for BlockAllocator<BuildingTxBatch> {
    type Next = BlockAllocator<BuildingProtocolTxBatch<WithoutNormalTxs>>;

    #[inline]
    fn next_state_impl(mut self) -> Self::Next {
        let remaining_free_space = self.unoccupied_space_in_bytes();
        self.protocol_txs = TxBin::init(remaining_free_space);
        // cast state
        let Self {
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
