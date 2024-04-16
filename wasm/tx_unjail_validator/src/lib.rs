//! A tx for a jailed validator to unjail themselves and re-enter the
//! validator sets.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let validator = Address::try_from_slice(&data[..])
        .wrap_err("Failed to decode the address of the validator to unjail")?;
    ctx.unjail_validator(&validator)
        .wrap_err("Failed to unjail validator")
}
