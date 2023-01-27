use namada_core::types::transaction::InitAccount;
use namada_core::types::key::{pk_key as the_keyyyyy};

use super::*;

pub fn init_account(ctx: &mut Ctx, data: InitAccount) -> TxResult {
    let address = ctx.init_account(&data.vp_code)?;

    let pk_threshold = key::threshold_key(&address);
    ctx.write(&pk_threshold, &data.threshold)?;
    
    let mut index = 0;
    for pk in data.public_keys.iter() {
        let pk_key = the_keyyyyy(&address, index);
        ctx.write(&pk_key, pk)?;
        index += 1;
    }

    Ok(())
}