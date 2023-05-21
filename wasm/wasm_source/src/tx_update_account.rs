//! A tx for updating an account's vp, threshold and associated public keys.
//! This tx wraps the validity predicate inside `SignedTxData` as
//! its input as declared in `shared` crate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let tx_data = transaction::UpdateAccount::try_from_slice(&data[..])
        .wrap_err("failed to decode UpdateAccount")?;
    debug_log!("update VP for: {:#?}", tx_data.address);

    account::update_account(ctx, tx_data)
}
