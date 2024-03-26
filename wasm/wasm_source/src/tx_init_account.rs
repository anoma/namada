//! A tx to initialize a new established address with a given public key and
//! a validity predicate.

use namada_tx_prelude::*;

#[transaction(gas = 885069)]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let tx_data = account::InitAccount::try_from_slice(&data[..])
        .wrap_err("Failed to decode InitAccount tx data")?;
    debug_log!("apply_tx called to init a new established account");

    let vp_code_sec = signed
        .get_section(&tx_data.vp_code_hash)
        .ok_or_err_msg("VP code section not found in tx")
        .map_err(|err| {
            ctx.set_commitment_sentinel();
            err
        })?
        .extra_data_sec()
        .ok_or_err_msg("VP code section must be tagged as extra")
        .map_err(|err| {
            ctx.set_commitment_sentinel();
            err
        })?;

    let address = ctx
        .init_account(vp_code_sec.code.hash(), &vp_code_sec.tag)
        .wrap_err("Failed to generate a new established account address")?;

    account::init_account(ctx, &address, tx_data)
        .wrap_err("Account creation failed")?;

    debug_log!("Created account {address}");
    Ok(())
}
