use namada_tx_prelude::*;

/// A tx that endlessly charges gas from the guest environment
#[transaction]
fn apply_tx(_ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    #[allow(clippy::empty_loop)]
    loop {}
}
