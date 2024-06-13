//! A tx for transparent token transfer.
//! This tx uses `token::TransparentTransfer` wrapped inside `SignedTxData`
//! as its input as declared in `namada` crate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let transfers = token::TransparentTransfer::try_from_slice(&data[..])
        .wrap_err("Failed to decode token::TransparentTransfer tx data")?;
    debug_log!("apply_tx called with transfer: {:#?}", transfers);

    for transfer in transfers.0 {
        token::transfer(
            ctx,
            &transfer.source,
            &transfer.target,
            &transfer.token,
            transfer.amount.amount(),
        )
        .wrap_err("Token transfer failed")?;
    }

    Ok(())
}
