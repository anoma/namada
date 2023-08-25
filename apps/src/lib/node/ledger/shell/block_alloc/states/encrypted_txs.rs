use std::marker::PhantomData;

use super::super::{AllocFailure, BlockAllocator, TxBin};
use super::{
    BuildingDecryptedTxBatch, BuildingEncryptedTxBatch,
    EncryptedTxBatchAllocator, NextStateImpl, TryAlloc, WithEncryptedTxs,
    WithoutEncryptedTxs,
};
use crate::node::ledger::shell::block_alloc::BlockResources;

impl TryAlloc for BlockAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>> {
    type Resources<'tx> = BlockResources<'tx>;

    #[inline]
    fn try_alloc(
        &mut self,
        resource_required: Self::Resources<'_>,
    ) -> Result<(), AllocFailure> {
        self.encrypted_txs.space.try_dump(resource_required.tx)?;
        self.encrypted_txs.gas.try_dump(resource_required.gas)
    }
}

impl NextStateImpl
    for BlockAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>>
{
    type Next = BlockAllocator<BuildingDecryptedTxBatch>;

    #[inline]
    fn next_state_impl(self) -> Self::Next {
        next_state(self)
    }
}

impl TryAlloc
    for BlockAllocator<BuildingEncryptedTxBatch<WithoutEncryptedTxs>>
{
    type Resources<'tx> = BlockResources<'tx>;

    #[inline]
    fn try_alloc(
        &mut self,
        _resource_required: Self::Resources<'_>,
    ) -> Result<(), AllocFailure> {
        Err(AllocFailure::Rejected {
            bin_resource_left: 0,
        })
    }
}

impl NextStateImpl
    for BlockAllocator<BuildingEncryptedTxBatch<WithoutEncryptedTxs>>
{
    type Next = BlockAllocator<BuildingDecryptedTxBatch>;

    #[inline]
    fn next_state_impl(self) -> Self::Next {
        next_state(self)
    }
}

#[inline]
fn next_state<Mode>(
    mut alloc: BlockAllocator<BuildingEncryptedTxBatch<Mode>>,
) -> BlockAllocator<BuildingDecryptedTxBatch> {
    alloc.encrypted_txs.space.shrink_to_fit();

    // decrypted txs can use as much space as they need - which
    // in practice will only be, at most, 1/3 of the block space
    // used by encrypted txs at the prev height
    let remaining_free_space = alloc.uninitialized_space_in_bytes();
    alloc.decrypted_txs = TxBin::init(remaining_free_space);

    // cast state
    let BlockAllocator {
        block,
        protocol_txs,
        encrypted_txs,
        decrypted_txs,
        ..
    } = alloc;

    BlockAllocator {
        _state: PhantomData,
        block,
        protocol_txs,
        encrypted_txs,
        decrypted_txs,
    }
}

impl TryAlloc for EncryptedTxBatchAllocator {
    type Resources<'tx> = BlockResources<'tx>;

    #[inline]
    fn try_alloc(
        &mut self,
        resource_required: Self::Resources<'_>,
    ) -> Result<(), AllocFailure> {
        match self {
            EncryptedTxBatchAllocator::WithEncryptedTxs(state) => {
                state.try_alloc(resource_required)
            }
            EncryptedTxBatchAllocator::WithoutEncryptedTxs(state) => {
                // NOTE: this operation will cause the allocator to
                // run out of memory immediately
                state.try_alloc(resource_required)
            }
        }
    }
}

impl NextStateImpl for EncryptedTxBatchAllocator {
    type Next = BlockAllocator<BuildingDecryptedTxBatch>;

    #[inline]
    fn next_state_impl(self) -> Self::Next {
        match self {
            EncryptedTxBatchAllocator::WithEncryptedTxs(state) => {
                state.next_state_impl()
            }
            EncryptedTxBatchAllocator::WithoutEncryptedTxs(state) => {
                state.next_state_impl()
            }
        }
    }
}
