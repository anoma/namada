//! A tx for IBC.
//! This tx executes an IBC operation according to the given IBC message as the
//! tx_data. This tx uses an IBC message wrapped inside
//! `key::ed25519::SignedTxData` as its input as declared in `ibc` crate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    log_string("\n\n\n HEY I'M ALIVE\n\n\n");
    let data = signed.data().ok_or_err_msg("Missing data")?;
    log_string("\n\n\n HEY I'M stilll ALIVE\n\n\n");
    ibc::ibc_actions(ctx).execute(&data).into_storage_result()
}
