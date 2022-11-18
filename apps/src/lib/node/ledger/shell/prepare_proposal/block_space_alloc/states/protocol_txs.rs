use std::marker::PhantomData;

use super::super::{AllocStatus, BlockSpaceAllocator, TxBin};
use super::{
    BuildingEncryptedTxBatch, BuildingProtocolTxBatch, NextStateImpl, State,
    WithEncryptedTxs, WithoutEncryptedTxs,
};

impl State for BlockSpaceAllocator<BuildingProtocolTxBatch> {
    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        // TODO: prioritize certain kinds of protocol txs;
        // this can be done at the `CheckTx` level,
        // we don't need the `TxBin`s to be aware
        // of different prioriy hints for protocol txs
        self.protocol_txs.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.protocol_txs.try_dump_all(txs)
    }
}

impl NextStateImpl<WithEncryptedTxs>
    for BlockSpaceAllocator<BuildingProtocolTxBatch>
{
    type Next = BlockSpaceAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>>;

    #[inline]
    fn next_state_impl(mut self) -> Self::Next {
        self.protocol_txs.shrink();

        // reserve space for encrypted txs
        let remaining_free_space = self.uninitialized_space_in_bytes();
        self.encrypted_txs = TxBin::init(remaining_free_space);

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
        self.protocol_txs.shrink();

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
