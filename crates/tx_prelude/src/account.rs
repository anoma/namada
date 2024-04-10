pub use namada_account::*;

use super::*;

#[inline]
pub fn init_account(
    ctx: &mut Ctx,
    owner: &Address,
    data: InitAccount,
) -> EnvResult<()> {
    namada_account::init_account_storage(
        ctx,
        owner,
        &data.public_keys,
        data.threshold,
    )
}
