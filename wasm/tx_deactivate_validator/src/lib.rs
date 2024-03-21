//! A tx to deactivate a validator.

use namada_tx_prelude::*;

#[transaction(gas = 340000)]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data")?;
    let validator = Address::try_from_slice(&data[..])
        .wrap_err("failed to decode an Address")?;
    ctx.deactivate_validator(&validator)
}
