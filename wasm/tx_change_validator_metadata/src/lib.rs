//! A tx for a validator to change various metadata, including its commission
//! rate.

use namada_tx_prelude::transaction::pos::MetaDataChange;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let MetaDataChange {
        validator,
        email,
        description,
        website,
        discord_handle,
        avatar,
        name,
        commission_rate,
    } = transaction::pos::MetaDataChange::try_from_slice(&data[..])
        .wrap_err("Failed to decode MetaDataChange value")?;
    ctx.change_validator_metadata(
        &validator,
        email,
        description,
        website,
        discord_handle,
        avatar,
        name,
        commission_rate,
    )
    .wrap_err("Failed to update validator's metadata")
}
