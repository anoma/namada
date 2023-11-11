//! A tx to reveal a public key of an implicit account.
//! This tx expects borsh encoded [`common::PublicKey`] in `tx_data` and it's
//! not signed as the authenticity of the public key can be trivially verified
//! against the address into which it's being written.

use namada_tx_prelude::key::common;
use namada_tx_prelude::*;

#[transaction(gas = 919818)]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let pk = common::PublicKey::try_from_slice(&data[..])
        .wrap_err("failed to decode common::PublicKey from tx_data")?;
    debug_log!("tx_reveal_pk called with pk: {pk}");
    key::reveal_pk(ctx, &pk)
}
