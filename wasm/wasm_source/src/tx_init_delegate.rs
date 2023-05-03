//! A tx to initialize a new delegate account

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let tx_data =
        transaction::governance::InitDelegate::try_from_slice(&data[..])
            .wrap_err("failed to decode InitDelegate.")?;
    debug_log!("apply_tx called to init a new delegatee account.");

    governance::init_delegate(ctx, tx_data)
}
