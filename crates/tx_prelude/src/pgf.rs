//! PGF related functions.

use namada_tx::data::pgf::UpdateStewardCommission;

use super::*;

/// Update the commission for a steward
pub fn update_steward_commission(
    ctx: &mut Ctx,
    data: UpdateStewardCommission,
) -> Result<()> {
    namada_governance::pgf::storage::update_commission(
        ctx,
        data.steward,
        data.commission,
    )?;

    Ok(())
}

/// Remove a steward
pub fn remove_steward(ctx: &mut Ctx, data: &Address) -> Result<()> {
    namada_governance::pgf::storage::remove_steward(ctx, data)?;

    Ok(())
}
