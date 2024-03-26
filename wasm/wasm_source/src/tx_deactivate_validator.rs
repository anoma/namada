//! A tx to deactivate a validator.

use namada_tx_prelude::*;

#[transaction(gas = 340000)]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data")?;
    let validator = Address::try_from_slice(&data[..]).wrap_err(
        "Failed to decode the address of the validator to deactivate",
    )?;
    ctx.deactivate_validator(&validator)
        .wrap_err("Failed to deactivate validator")
}
