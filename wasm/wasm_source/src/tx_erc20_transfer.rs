//! A tx for token transfer.
//! This tx uses `token::Transfer` wrapped inside `SignedTxData`
//! as its input as declared in `shared` crate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let transfer = token::Erc20Transfer::try_from_slice(&data[..])
        .wrap_err("failed to decode token::Erc20Transfer")?;
    debug_log!("apply_tx called with transfer: {:#?}", transfer);
    let token::Erc20Transfer {
        source,
        target,
        token,
        sub_prefix,
        amount,
    } = transfer;
    token::transfer(
        ctx,
        &source,
        &target,
        &token,
        Some(sub_prefix),
        amount,
        &None,
        &None,
    )
}
