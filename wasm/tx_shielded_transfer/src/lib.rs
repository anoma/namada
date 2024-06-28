//! A tx for shielded token transfer.

use namada_tx_prelude::action::{Action, MaspAction, Write};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let transfer = token::ShieldedTransfer::try_from_slice(&data[..])
        .wrap_err("Failed to decode token::ShieldedTransfer tx data")?;
    debug_log!("apply_tx called with transfer: {:#?}", transfer);

    let masp_section_ref = transfer.section_hash;
    let shielded = tx_data
        .tx
        .get_masp_section(&masp_section_ref)
        .cloned()
        .ok_or_err_msg("Unable to find required shielded section in tx data")
        .map_err(|err| {
            ctx.set_commitment_sentinel();
            err
        })?;
    token::utils::handle_masp_tx(ctx, &shielded)
        .wrap_err("Encountered error while handling MASP transaction")?;
    update_masp_note_commitment_tree(&shielded)
        .wrap_err("Failed to update the MASP commitment tree")?;
    ctx.push_action(Action::Masp(MaspAction { masp_section_ref }))?;
    Ok(())
}
