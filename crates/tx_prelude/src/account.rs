//! Account related functions.

pub use namada_account::*;

use super::*;

/// Init the storage of a new account
#[inline]
pub fn init_account(
    ctx: &mut Ctx,
    owner: &Address,
    data: InitAccount,
) -> Result<()> {
    namada_account::init_account_storage(
        ctx,
        owner,
        &data.public_keys,
        data.threshold,
    )
}
