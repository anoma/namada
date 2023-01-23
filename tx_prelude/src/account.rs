use namada_core::types::key::pk_key;
use namada_core::types::transaction::InitAccount;

use super::*;

pub fn init_account(ctx: &mut Ctx, data: InitAccount) -> EnvResult<Address> {
    let address = ctx.init_account(&data.vp_code_hash)?;

    let pk_threshold = key::threshold_key(&address);
    ctx.write(&pk_threshold, data.threshold)?;

    for (pk, index) in data.public_keys.iter().zip(0u64..) {
        let pk_key = pk_key(&address, index);
        ctx.write(&pk_key, pk)?;
    }

    Ok(address)
}
