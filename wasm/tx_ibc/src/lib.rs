//! A tx for IBC.
//! This tx executes an IBC operation according to the given IBC message as the
//! tx_data. This tx uses an IBC message wrapped inside
//! `key::ed25519::SignedTxData` as its input as declared in `ibc` crate.

use namada_tx_prelude::action::{Action, MaspAction, Write};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let transfer =
        ibc::ibc_actions(ctx).execute(&data).into_storage_result()?;

    if let Some(masp_section_ref) =
        transfer.and_then(|transfer| transfer.shielded_section_hash)
    {
        let shielded = tx_data
            .tx
            .get_section(&masp_section_ref)
            .and_then(|x| x.as_ref().masp_tx())
            .ok_or_err_msg(
                "Unable to find required shielded section in tx data",
            )
            .map_err(|err| {
                ctx.set_commitment_sentinel();
                err
            })?;
        token::utils::handle_masp_tx(ctx, &shielded)
            .wrap_err("Encountered error while handling MASP transaction")?;
        update_masp_note_commitment_tree(&shielded)
            .wrap_err("Failed to update the MASP commitment tree")?;
        ctx.push_action(Action::Masp(MaspAction { masp_section_ref }))?;
    }

    Ok(())
}
