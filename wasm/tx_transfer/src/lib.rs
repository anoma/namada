//! A tx for token transfer.
//! This tx uses `token::Transfer` wrapped inside `SignedTxData`
//! as its input as declared in `namada` crate.

use namada_tx_prelude::*;

#[transaction(gas = 1703358)]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let transfer = token::Transfer::try_from_slice(&data[..])
        .wrap_err("failed to decode token::Transfer")?;
    debug_log!("apply_tx called with transfer: {:#?}", transfer);

    token::transfer(
        ctx,
        &transfer.source,
        &transfer.target,
        &transfer.token,
        transfer.amount,
    )?;

    let shielded = transfer
        .shielded
        .as_ref()
        .map(|hash| {
            signed
                .get_section(hash)
                .and_then(|x| x.as_ref().masp_tx())
                .ok_or_err_msg("unable to find shielded section")
                .map_err(|err| {
                    ctx.set_commitment_sentinel();
                    err
                })
        })
        .transpose()?;
    if let Some(shielded) = shielded {
        token::utils::handle_masp_tx(ctx, &shielded, transfer.key.as_deref())?;
        update_masp_note_commitment_tree(&shielded)?;
    }
    Ok(())
}
