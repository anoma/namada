use std::marker::PhantomData;

use super::super::{AllocStatus, BlockSpaceAllocator, TxBin};
use super::{
    BuildingEncryptedTxBatch, BuildingProtocolTxBatch, State, WithEncryptedTxs,
    WithoutEncryptedTxs,
};

impl State<WithEncryptedTxs> for BlockSpaceAllocator<BuildingProtocolTxBatch> {
    type Next = BlockSpaceAllocator<BuildingEncryptedTxBatch<WithEncryptedTxs>>;

    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        self.protocol_txs.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.protocol_txs.try_dump_all(txs)
    }

    #[inline]
    fn next_state(mut self) -> Self::Next {
        self.protocol_txs.shrink();

        // reserve space for encrypted txs
        let free_space = self.uninitialized_space_in_bytes();
        self.protocol_txs = TxBin::init(free_space);

        // cast state
        let Self {
            max_block_space_in_bytes,
            protocol_txs,
            encrypted_txs,
            decrypted_txs,
            ..
        } = self;

        BlockSpaceAllocator {
            _state: PhantomData,
            max_block_space_in_bytes,
            protocol_txs,
            encrypted_txs,
            decrypted_txs,
        }
    }
}

impl State<WithoutEncryptedTxs>
    for BlockSpaceAllocator<BuildingProtocolTxBatch>
{
    type Next =
        BlockSpaceAllocator<BuildingEncryptedTxBatch<WithoutEncryptedTxs>>;

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

    #[inline]
    fn next_state(mut self) -> Self::Next {
        self.protocol_txs.shrink();

        // cast state
        let Self {
            max_block_space_in_bytes,
            protocol_txs,
            encrypted_txs,
            decrypted_txs,
            ..
        } = self;

        BlockSpaceAllocator {
            _state: PhantomData,
            max_block_space_in_bytes,
            protocol_txs,
            encrypted_txs,
            decrypted_txs,
        }
    }
}
