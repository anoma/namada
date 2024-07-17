//! A tx for IBC.
//! This tx executes an IBC operation according to the given IBC message as the
//! tx_data. This tx uses an IBC message wrapped inside
//! `key::ed25519::SignedTxData` as its input as declared in `ibc` crate.

use namada_tx_prelude::action::{Action, MaspAction, Write};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let (transfer, masp_tx) =
        ibc::ibc_actions(ctx).execute(&data).into_storage_result()?;

    let masp_section_ref = transfer
        .map(|transfers| {
            token::multi_transfer(ctx, &transfers)
                .wrap_err("Token transfer failed")
                .map(|_| transfers.shielded_section_hash)
        })
        .transpose()?
        .flatten();
    let shielded = masp_section_ref
        .map(|masp_section_ref| ctx.get_masp_tx(&tx_data, &masp_section_ref))
        .transpose()?
        .or(masp_tx);
    if let Some(shielded) = shielded {
        masp::handle_masp_tx(ctx, &shielded)?;
        let action = if let Some(masp_section_ref) = masp_section_ref {
            Action::Masp(MaspAction { masp_section_ref })
        } else {
            Action::IbcShielding
        };
        ctx.push_action(action)?;
    }

    Ok(())
}
