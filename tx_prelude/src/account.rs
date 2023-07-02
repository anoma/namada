use namada_core::types::transaction::account::InitAccount;

use super::*;

pub fn init_account(ctx: &mut Ctx, owner: &Address, data: InitAccount) -> EnvResult<Address> {
    storage_api::account::init_account_storage(
        ctx,
        &owner,
        &data.public_keys,
        data.threshold,
    )?;

    Ok(owner.to_owned())
}
