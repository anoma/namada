use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let _data = tx_data
        .to_ref()
        .data()
        .ok_or_err_msg("Missing data")
        .inspect_err(|_| {
            ctx.set_commitment_sentinel();
        })?;
    Ok(())
}
