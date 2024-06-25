//! A tx for shielding token transfer.

use namada_tx_prelude::action::{Action, MaspAction, Write};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let transfers = token::ShieldingMultiTransfer::try_from_slice(&data[..])
        .wrap_err("Failed to decode token::ShieldingTransfer tx data")?;
    debug_log!("apply_tx called with transfer: {:#?}", transfers);

    for transfer in transfers.data {
        token::transfer(
            ctx,
            &transfer.source,
            &address::MASP,
            &transfer.token,
            transfer.amount.amount(),
        )
        .wrap_err("Token transfer failed")?;
    }

    let masp_section_ref = transfers.shielded_section_hash;
    let shielded = tx_data
        .tx
        .get_section(&masp_section_ref)
        .and_then(|x| x.as_ref().masp_tx())
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
