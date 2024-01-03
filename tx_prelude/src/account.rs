use namada_tx::data::account::InitAccount;

use super::*;

pub fn init_account(
    ctx: &mut Ctx,
    owner: &Address,
    data: InitAccount,
) -> EnvResult<Address> {
    namada_account::init_account_storage(
        ctx,
        owner,
        &data.public_keys,
        data.threshold,
    )?;

    Ok(owner.to_owned())
}
