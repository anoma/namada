//! A tx for IBC operations except for transfers.
//! This tx executes an IBC operation according to the given IBC message as the
//! tx_data. This tx uses an IBC message wrapped inside
//! `key::ed25519::SignedTxData` as its input as declared in `ibc` crate.

use namada_tx_prelude::action::{Action, MaspAction, Write};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let ibc_message = IbcMessage::try_from_slice(&data[..])
        .wrap_err("Failed to decode IbcMessage")?;
    let envelope = match ibc_message {
        ibc::IbcMessage::Envelope(env) => env,
        _ => {
            return Err(Error::new_const(
                "IBC message should have MsgEnvelope",
            ));
        }
    };

    let shielded = ibc::ibc_actions(ctx)
        .execute_with_envelope(&envelope)
        .into_storage_result()?;

    if let Some(shielded) = shielded {
        masp::handle_masp_tx(ctx, &shielded)?;
        ctx.push_action(Action::IbcShielding)?;
    }

    Ok(())
}
