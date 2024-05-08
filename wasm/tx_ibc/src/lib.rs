//! A tx for IBC.
//! This tx executes an IBC operation according to the given IBC message as the
//! tx_data. This tx uses an IBC message wrapped inside
//! `key::ed25519::SignedTxData` as its input as declared in `ibc` crate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    // let data = signed.data().ok_or_err_msg("Missing data").or_else(|err| {
    //                 ctx.set_commitment_sentinel();
    //                 Err(err)
    // })?;

    // let transfer =
    // ibc::ibc_actions(ctx).execute(&data).into_storage_result()?;

    // Temp. workaround for <https://github.com/anoma/namada/issues/1831>
    let transfer = tx_ibc_execute()?;

    if let Some(transfer) = transfer {
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
            token::utils::handle_masp_tx(ctx, &shielded)?;
            update_masp_note_commitment_tree(&shielded)?;
        }
    }

    Ok(())
}
