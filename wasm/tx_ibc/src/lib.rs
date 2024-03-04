//! A tx for IBC.
//! This tx executes an IBC operation according to the given IBC message as the
//! tx_data. This tx uses an IBC message wrapped inside
//! `key::ed25519::SignedTxData` as its input as declared in `ibc` crate.

use namada_tx_prelude::*;

#[transaction(gas = 585022)]
fn apply_tx(_ctx: &mut Ctx, _tx_data: Tx) -> TxResult {
    // let signed = tx_data;
    // let data = signed.data().ok_or_err_msg("Missing data").or_else(|err| {
    //                 ctx.set_commitment_sentinel();
    //                 Err(err)
    // })?;

    // ibc::ibc_actions(ctx).execute(&data).into_storage_result()

    // Temp. workaround for <https://github.com/anoma/namada/issues/1831>
    tx_ibc_execute();
    Ok(())
}
