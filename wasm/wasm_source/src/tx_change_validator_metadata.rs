//! A tx for a validator to change various metadata, including its commission
//! rate.

use namada_tx_prelude::transaction::pos::MetaDataChange;
use namada_tx_prelude::*;

// TODO: need to benchmark gas!!!
#[transaction(gas = 220000)]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data")?;
    let MetaDataChange {
        validator,
        email,
        description,
        website,
        discord_handle,
        avatar,
        commission_rate,
    } = transaction::pos::MetaDataChange::try_from_slice(&data[..])
        .wrap_err("failed to decode Dec value")?;
    ctx.change_validator_metadata(
        &validator,
        email,
        description,
        website,
        discord_handle,
        avatar,
        commission_rate,
    )
}
