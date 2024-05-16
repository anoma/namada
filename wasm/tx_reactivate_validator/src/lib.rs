//! A tx to reactivate a validator.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let validator = Address::try_from_slice(&data[..])
        .wrap_err("Failed to decode address of the validator to reactivate")?;
    ctx.reactivate_validator(&validator)
        .wrap_err("Failed to reactivate validator")
}
