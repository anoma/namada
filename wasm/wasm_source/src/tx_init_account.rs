//! A tx to initialize a new established address with a given public key and
//! a validity predicate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let tx_data = transaction::InitAccount::try_from_slice(&data[..])
        .wrap_err("failed to decode InitAccount")?;
    debug_log!("apply_tx called to init a new established account");

    match account::init_account(ctx, tx_data) {
        Ok(account_address) => {
            debug_log!("Created account {}", account_address.encode())
        }
        Err(err) => {
            debug_log!("Account creation failed with: {}", err);
            panic!()
        }
    }
    Ok(())
}
