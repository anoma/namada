use namada::proto::Tx;
use namada::types::transaction::process_tx;
use namada::types::transaction::tx_types::TxType;

use super::super::{AllocStatus, BlockSpaceAllocator};
use super::{
    FillingRemainingSpace, RemainingBatchAllocator, TryAlloc, WithEncryptedTxs,
    WithoutEncryptedTxs,
};

impl TryAlloc for BlockSpaceAllocator<FillingRemainingSpace<WithEncryptedTxs>> {
    #[inline]
    fn try_alloc<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
        self.block.try_dump(tx)
    }
}

// TODO: limit txs that can go in the bins at this level? so we don't misuse
// the abstraction. it's not like we can't push encrypted txs into the bins,
// right now...
impl TryAlloc
    for BlockSpaceAllocator<FillingRemainingSpace<WithoutEncryptedTxs>>
{
    #[inline]
    fn try_alloc<'tx>(&mut self, tx: &'tx [u8]) -> AllocStatus<'tx> {
        self.block.try_dump(tx)
    }
}

impl TryAlloc for RemainingBatchAllocator {
    #[inline]
    fn try_alloc<'tx>(&mut self, tx_bytes: &'tx [u8]) -> AllocStatus<'tx> {
        match self {
            RemainingBatchAllocator::WithEncryptedTxs(state) => {
                state.try_alloc(tx_bytes)
            }
            RemainingBatchAllocator::WithoutEncryptedTxs(state) => {
                let tx = Tx::try_from(tx_bytes)
                    .expect("Tx passed mempool validation");
                if let Ok(TxType::Wrapper(_)) = process_tx(tx) {
                    // do not allocate anything if we
                    // find an encrypted tx
                    AllocStatus::Accepted
                } else {
                    state.try_alloc(tx_bytes)
                }
            }
        }
    }
}
