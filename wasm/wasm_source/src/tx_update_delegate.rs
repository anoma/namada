//! A tx to add/remove a new delegatee for a delegator

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let tx_data = transaction::governance::UpdateDelegate::try_from_slice(&data[..])
        .wrap_err("failed to decode UpdateDelegate.")?;
    debug_log!("apply_tx called to update a governance delegation.");

    governance::update_delegate_for(ctx, tx_data)
}
