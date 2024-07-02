//! A tx for transparent token transfer.
//! This tx uses `token::TransparentTransfer` wrapped inside `SignedTxData`
//! as its input as declared in `namada` crate.

use std::collections::BTreeMap;

use namada_tx_prelude::action::{Action, MaspAction, Write};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let transfers = token::Transfer::try_from_slice(&data[..])
        .wrap_err("Failed to decode token::TransparentTransfer tx data")?;
    debug_log!("apply_tx called with transfer: {:#?}", transfers);

    // Prepare the sources of the multi-transfer
    let sources = transfers
        .sources
        .into_iter()
        .map(|(account, amount)| {
            ((account.owner, account.token), amount.amount())
        })
        .collect::<BTreeMap<_, _>>();

    // Prepare the target of the multi-transfer
    let targets = transfers
        .targets
        .into_iter()
        .map(|(account, amount)| {
            ((account.owner, account.token), amount.amount())
        })
        .collect::<BTreeMap<_, _>>();

    // Effect the multi transfer
    token::multi_transfer(ctx, &sources, &targets)
        .wrap_err("Token transfer failed")?;

    // Apply the shielded transfer if there is a link to one
    if let Some(masp_section_ref) = transfers.shielded_section_hash {
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
