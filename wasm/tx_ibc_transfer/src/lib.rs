//! A tx for IBC transfer.
//! This tx executes an IBC transfer according to the given IBC message as the
//! tx_data. This tx uses an IBC message wrapped inside
//! `key::ed25519::SignedTxData` as its input as declared in `ibc` crate.

use namada_tx_prelude::action::{Action, MaspAction, Write};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let ibc_message = IbcMessage::try_from_slice(&data[..])
        .wrap_err("Failed to decode IbcMessage")?;
    let message = match ibc_message {
        ibc::IbcMessage::Transfer(msg) => msg,
        _ => {
            return Err(Error::new_const(
                "IBC message should have MsgTransfer",
            ));
        }
    };
    let transfer = ibc::ibc_actions(ctx)
        .execute_transfer(&message)
        .into_storage_result()?;

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
        .transpose()?;
    if let Some(shielded) = shielded {
        masp::handle_masp_tx(ctx, &shielded)?;
        if let Some(masp_section_ref) = masp_section_ref {
            ctx.push_action(Action::Masp(MaspAction { masp_section_ref }))?;
        }
    }

    Ok(())
}
