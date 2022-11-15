use std::marker::PhantomData;

use super::super::{thres, AllocStatus, BlockSpaceAllocator, TxBin};
use super::{BuildingDecryptedTxBatch, BuildingProtocolTxBatch, State};

impl State for BlockSpaceAllocator<BuildingDecryptedTxBatch> {
    type Next = BlockSpaceAllocator<BuildingProtocolTxBatch>;

    #[inline]
    fn try_alloc(&mut self, tx: &[u8]) -> AllocStatus {
        self.decrypted_txs.try_dump(tx)
    }

    #[inline]
    fn try_alloc_batch<'tx, T>(&mut self, txs: T) -> AllocStatus
    where
        T: IntoIterator<Item = &'tx [u8]> + 'tx,
    {
        self.decrypted_txs.try_dump_all(txs)
    }

    #[inline]
    fn next_state(mut self) -> Self::Next {
        // seal decrypted txs
        self.decrypted_txs.allotted_space_in_bytes =
            self.decrypted_txs.current_space_in_bytes;

        // reserve space for protocol txs
        let uninit = self.uninitialized_space_in_bytes();
        self.protocol_txs = TxBin::init_over_ratio(uninit, thres::ONE_THIRD);

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
