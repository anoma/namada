//! A tx for IBC.
//! This tx executes an IBC operation according to the given IBC message as the
//! tx_data. This tx uses an IBC message as its input.

use namada_tx_prelude::action::{Action, MaspAction, Write};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let data = ibc::ibc_actions(ctx)
        .execute::<token::Transfer>(&data)
        .into_storage_result()?;

    let (maybe_masp_refs, mut token_addrs) =
        if let Some(transfers) = data.transparent {
            let (_debited_accounts, tokens) =
                if let Some(transparent) = transfers.transparent_part() {
                    token::apply_transparent_transfers(ctx, transparent)
                        .wrap_err("Transparent token transfer failed")?
                } else {
                    Default::default()
                };

            (transfers.shielded_data, tokens)
        } else {
            (None, Default::default())
        };

    token_addrs.extend(data.ibc_tokens);

    let maybe_masp_tx = if let Some(shielded) = maybe_masp_refs {
        Some(
            tx_data
                .tx
                .get_masp_section(&shielded.masp_tx_id)
                .cloned()
                .ok_or_err_msg(
                    "Unable to find required shielded section in tx data",
                )
                .inspect_err(|_| {
                    ctx.set_commitment_sentinel();
                })?,
        )
    } else {
        data.shielded
            .map(|ibc_shielding_data| ibc_shielding_data.masp_tx)
    };

    if let Some(masp_tx) = maybe_masp_tx {
        token::utils::handle_masp_tx(ctx, &masp_tx)
            .wrap_err("Encountered error while handling MASP transaction")?;
        update_masp_note_commitment_tree(&masp_tx)
            .wrap_err("Failed to update the MASP commitment tree")?;
        if let Some(masp_refs) = maybe_masp_refs {
            ctx.push_action(Action::Masp(MaspAction::MaspSectionRef(
                masp_refs.masp_tx_id,
            )))?;
            ctx.push_action(Action::Masp(MaspAction::FmdSectionRef(
                masp_refs.flag_ciphertext_sechash,
            )))?;
        } else {
            ctx.push_action(Action::IbcShielding)?;
        }
        token::update_undated_balances(ctx, &masp_tx, token_addrs)?;
    }

    Ok(())
}
