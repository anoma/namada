//! A tx for token transfer.
//! This tx uses `token::Transfer` wrapped inside `SignedTxData`
//! as its input as declared in `shared` crate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..]).unwrap();
    let transfer =
        token::Transfer::try_from_slice(&signed.data.unwrap()[..]).unwrap();
    debug_log!("apply_tx called with transfer: {:#?}", transfer);
    let token::Transfer {
        source,
        target,
        token,
        amount,
        key,
        shielded,
    } = transfer;
    token::transfer(&source, &target, &token, amount, &key, &shielded)
}
