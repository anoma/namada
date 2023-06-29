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

    let vp_code = signed
        .get_section(&tx_data.vp_code_hash)
        .ok_or_err_msg("vp code section not found")?
        .extra_data_sec()
        .ok_or_err_msg("vp code section must be tagged as extra")?
        .code
        .hash();
    let address = ctx.init_account(vp_code)?;
    let pk_key = key::pk_key(&address);
    ctx.write(&pk_key, &tx_data.public_key)?;
    Ok(())
}
