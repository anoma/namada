use namada_tx::data::pgf::UpdateStewardCommission;

use super::*;

pub fn update_steward_commission(
    ctx: &mut Ctx,
    data: UpdateStewardCommission,
) -> EnvResult<()> {
    namada_governance::pgf::storage::update_commission(
        ctx,
        data.steward,
        data.commission,
    )?;

    Ok(())
}

pub fn remove_steward(ctx: &mut Ctx, data: &Address) -> EnvResult<()> {
    namada_governance::pgf::storage::remove_steward(ctx, data)?;

    Ok(())
}
