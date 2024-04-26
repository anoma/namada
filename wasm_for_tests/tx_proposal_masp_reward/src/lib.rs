use std::str::FromStr;

use dec::Dec;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    let native_token = ctx.get_native_token()?;
    let shielded_rewards_key =
        token::storage_key::masp_max_reward_rate_key(&native_token);

    ctx.write(&shielded_rewards_key, Dec::from_str("0.05").unwrap())?;

    Ok(())
}
