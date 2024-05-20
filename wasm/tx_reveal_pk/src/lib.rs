//! A tx to reveal a public key of an implicit account.
//! This tx expects borsh encoded [`common::PublicKey`] in `tx_data` and it's
//! not signed as the authenticity of the public key can be trivially verified
//! against the address into which it's being written.

use namada_tx_prelude::key::common;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let pk = common::PublicKey::try_from_slice(&data[..])
        .wrap_err("Failed to decode public key to reveal from the tx data")?;
    debug_log!("tx_reveal_pk called with pk: {pk}");
    key::reveal_pk(ctx, &pk)
        .wrap_err("Failed to reveal the implicit account's public key")
}
