//! A tx for transparent token transfer.
//! This tx uses `token::TransparentTransfer` wrapped inside `SignedTxData`
//! as its input as declared in `namada` crate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let transfers = token::Transfer::try_from_slice(&data[..])
        .wrap_err("Failed to decode token::TransparentTransfer tx data")?;
    debug_log!("apply_tx called with transfer: {:#?}", transfers);

    token::multi_transfer(ctx, transfers, &tx_data)
}
