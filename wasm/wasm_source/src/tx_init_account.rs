//! A tx to initialize a new established address with a given public key and
//! a validity predicate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data")?;
    let tx_data = transaction::InitAccount::try_from_slice(&data[..])
        .wrap_err("failed to decode InitAccount")?;
    debug_log!("apply_tx called to init a new established account");

    let address = ctx.init_account(
        &signed.extra().ok_or_err_msg("extra data containing code not found")?
    )?;
    let pk_key = key::pk_key(&address);
    ctx.write(&pk_key, &tx_data.public_key)?;
    Ok(())
}
