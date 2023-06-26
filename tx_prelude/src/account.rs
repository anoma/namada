use namada_core::types::transaction::account::InitAccount;

use super::*;

pub fn init_account(ctx: &mut Ctx, data: InitAccount) -> EnvResult<Address> {
    let address = ctx.init_account(data.vp_code_hash)?;
    storage_api::account::init_account_storage(
        ctx,
        &address,
        &data.public_keys,
        data.threshold,
    )?;

    Ok(address)
}
