//! A tx for a jailed validator to reactivate themselves and re-enter the
//! validator sets.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let validator = Address::try_from_slice(&data[..])
        .wrap_err("failed to decode an Address")?;
    ctx.reactivate_validator(&validator)
}
