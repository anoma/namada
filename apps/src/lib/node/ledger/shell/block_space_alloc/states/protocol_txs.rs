use std::marker::PhantomData;

use super::super::{threshold, AllocFailure, BlockSpaceAllocator, TxBin};
use super::{
    BuildingEncryptedTxBatch, BuildingProtocolTxBatch, NextStateImpl, TryAlloc,
    WithEncryptedTxs, WithoutEncryptedTxs,
};

impl TryAlloc for BlockSpaceAllocator<BuildingProtocolTxBatch> {
    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> Result<(), AllocFailure> {
        self.protocol_txs.try_dump(tx)
    }
}

impl NextStateImpl<WithEncryptedTxs>
    for BlockSpaceAllocator<BuildingProtocolTxBatch>
{
    type Next = BlockSpaceAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>>;

    #[inline]
    fn next_state_impl(mut self) -> Self::Next {
        self.protocol_txs.shrink_to_fit();

        // reserve space for encrypted txs; encrypted txs can use up to
        // 1/3 of the max block space; the rest goes to protocol txs, once
        // more
        let one_third_of_block_space =
            threshold::ONE_THIRD.over(self.block.allotted_space_in_bytes);
        let remaining_free_space = self.uninitialized_space_in_bytes();
        self.encrypted_txs = TxBin::init(std::cmp::min(
            one_third_of_block_space,
            remaining_free_space,
        ));

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

impl NextStateImpl<WithoutEncryptedTxs>
    for BlockSpaceAllocator<BuildingProtocolTxBatch>
{
    type Next =
        BlockSpaceAllocator<BuildingEncryptedTxBatch<WithoutEncryptedTxs>>;

    #[inline]
    fn next_state_impl(mut self) -> Self::Next {
        self.protocol_txs.shrink_to_fit();

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
