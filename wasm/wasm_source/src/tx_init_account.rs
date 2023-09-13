//! A tx to initialize a new established address with a given public key and
//! a validity predicate.

use namada_tx_prelude::*;

#[transaction(gas = 230000)]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data")?;
    let tx_data = transaction::account::InitAccount::try_from_slice(&data[..])
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

    match account::init_account(ctx, &address, tx_data) {
        Ok(address) => {
            debug_log!("Created account {}", address.encode(),)
        }
        Err(err) => {
            debug_log!("Account creation failed with: {}", err);
            panic!()
        }
    }
    Ok(())
}
