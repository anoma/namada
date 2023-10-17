use namada_core::types::transaction::pgf::UpdateStewardCommission;

use super::*;

pub fn update_steward_commission(
    ctx: &mut Ctx,
    data: UpdateStewardCommission,
) -> EnvResult<()> {
    storage_api::pgf::update_commission(ctx, data.steward, data.commission)?;

    Ok(())
}

pub fn remove_steward(ctx: &mut Ctx, data: &Address) -> EnvResult<()> {
    storage_api::pgf::remove_steward(ctx, data)?;

    Ok(())
}
