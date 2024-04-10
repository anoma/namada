//! A tx to update the commission distribution for a steward

use namada_tx_prelude::action::{Action, PgfAction, Write};
use namada_tx_prelude::transaction::pgf::UpdateStewardCommission;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let steward_commission = UpdateStewardCommission::try_from_slice(&data[..])
        .wrap_err("Failed to decode an UpdateStewardCommission tx data")?;

    // The tx must be authorized by the source address
    ctx.insert_verifier(&steward_commission.steward)?;

    ctx.push_action(Action::Pgf(PgfAction::UpdateStewardCommission(
        steward_commission.steward.clone(),
    )))?;

    pgf::update_steward_commission(ctx, steward_commission)
        .wrap_err("Failed to update steward commission rate")?;

    Ok(())
}
