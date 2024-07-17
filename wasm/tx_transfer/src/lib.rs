//! A tx for transparent token transfer.
//! This tx uses `token::TransparentTransfer` wrapped inside `SignedTxData`
//! as its input as declared in `namada` crate.

use namada_tx_prelude::action::{Action, MaspAction, Write};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let transfers = token::Transfer::try_from_slice(&data[..])
        .wrap_err("Failed to decode token::TransparentTransfer tx data")?;
    debug_log!("apply_tx called with transfer: {:#?}", transfers);

    // Effect the multi transfer
    token::multi_transfer(ctx, &transfers).wrap_err("Token transfer failed")?;

    // Apply the shielded transfer if there is a link to one
    if let Some(masp_section_ref) = transfers.shielded_section_hash {
        let shielded = ctx.get_masp_tx(&tx_data, &masp_section_ref)?;
        masp::handle_masp_tx(ctx, &shielded)?;
        ctx.push_action(Action::Masp(MaspAction { masp_section_ref }))?;
    }

    Ok(())
}
