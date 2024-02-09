//! A tx to initialize a new established address with a given public key.

use namada_tx_prelude::*;

#[transaction(gas = 885069)]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let tx_data = account::InitAccount::try_from_slice(&data[..])
        .wrap_err("failed to decode InitAccount")?;
    debug_log!("apply_tx called to init a new established account");

    let address = ctx.init_account()?;

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
