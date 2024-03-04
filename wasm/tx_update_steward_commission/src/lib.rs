//! A tx to update the commission distribution for a steward

use namada_tx_prelude::transaction::pgf::UpdateStewardCommission;
use namada_tx_prelude::*;

#[transaction(gas = 1222239)]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let steward_commission = UpdateStewardCommission::try_from_slice(&data[..])
        .wrap_err("failed to decode an UpdateStewardCommission")?;

    pgf::update_steward_commission(ctx, steward_commission)?;

    Ok(())
}
