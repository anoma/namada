//! A tx to resign as a steward

use namada_tx_prelude::action::{Action, PgfAction, Write};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let steward_address = Address::try_from_slice(&data[..]).wrap_err(
        "Failed to decode the address of the PGF steward to remove",
    )?;

    // The tx must be authorized by the source address
    ctx.insert_verifier(&steward_address)?;

    pgf::remove_steward(ctx, &steward_address)
        .wrap_err("Failed to remove PGF steward")?;
    debug_log!("Removed PGF steward {steward_address}");

    Ok(())
}
