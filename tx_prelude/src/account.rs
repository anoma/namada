use namada_core::types::transaction::InitAccount;
use namada_core::types::key;

use super::*;

pub fn init_account(ctx: &mut Ctx, data: InitAccount) -> TxResult {
    let address = ctx.init_account(&data.vp_code)?;

    let pk_threshold = key::threshold_key(&address);
    ctx.write(&pk_threshold, &data.threshold)?;
    
    for (pk, index) in data.public_keys.iter().zip(0u64..) {
        let pk_key = key::pk_key(&address, index);
        ctx.write(&pk_key, pk)?;
    }

    Ok(())
}