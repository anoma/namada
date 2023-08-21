use namada_core::types::transaction::pgf::UpdateStewardCommission;

use super::*;

pub fn update_steward_commission(
    ctx: &mut Ctx,
    data: UpdateStewardCommission,
) -> EnvResult<()> {
    let is_steward = storage_api::pgf::is_steward(ctx, &data.steward)?;
    if !is_steward {
        return Ok(());
    }

    storage_api::pgf::update_commission(ctx, data.steward, data.commission)?;

    Ok(())
}

pub fn remove_steward(ctx: &mut Ctx, data: &Address) -> EnvResult<()> {
    storage_api::pgf::remove_steward(ctx, data)?;

    Ok(())
}
