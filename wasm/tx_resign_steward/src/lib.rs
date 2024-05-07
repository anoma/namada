//! A tx to resign as a steward

use namada_tx_prelude::action::{Action, PgfAction, Write};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let steward_address = Address::try_from_slice(&data[..]).wrap_err(
        "Failed to decode the address of the PGF steward to remove",
    )?;

    // The tx must be authorized by the source address
    ctx.insert_verifier(&steward_address)?;

    ctx.push_action(Action::Pgf(PgfAction::ResignSteward(
        steward_address.clone(),
    )))?;

    pgf::remove_steward(ctx, &steward_address)
        .wrap_err("Failed to remove PGF steward")?;
    debug_log!("Removed PGF steward {steward_address}");

    Ok(())
}
