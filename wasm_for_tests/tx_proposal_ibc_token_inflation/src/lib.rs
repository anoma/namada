use std::str::FromStr;

use dec::Dec;
use namada_tx_prelude::*;

// Denom of tokens over IBC is always zero
const IBC_TOKEN_DENOM: u8 = 0;
const CHANNEL_ID: &str = "channel-0";
const BASE_TOKEN: &str = "samoleans";

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    let ibc_denom = format!("transfer/{CHANNEL_ID}/{BASE_TOKEN}");
    let ibc_token = ibc::ibc_token(&ibc_denom);

    let shielded_token_last_inflation_key =
        token::storage_key::masp_last_inflation_key(&ibc_token);
    let shielded_token_last_locked_amount_key =
        token::storage_key::masp_last_locked_amount_key(&ibc_token);
    let shielded_token_max_rewards_key =
        token::storage_key::masp_max_reward_rate_key(&ibc_token);
    let shielded_token_target_locked_amount_key =
        token::storage_key::masp_locked_amount_target_key(&ibc_token);
    let shielded_token_kp_gain_key =
        token::storage_key::masp_kp_gain_key(&ibc_token);
    let shielded_token_kd_gain_key =
        token::storage_key::masp_kd_gain_key(&ibc_token);

    let token_map_key = token::storage_key::masp_token_map_key();
    let mut token_map: masp::TokenMap =
        ctx.read(&token_map_key)?.unwrap_or_default();
    token_map.insert(ibc_denom, ibc_token);
    ctx.write(&token_map_key, token_map)?;

    ctx.write(&shielded_token_last_inflation_key, token::Amount::zero())?;
    ctx.write(
        &shielded_token_last_locked_amount_key,
        token::Amount::zero(),
    )?;
    ctx.write(
        &shielded_token_max_rewards_key,
        Dec::from_str("0.01").unwrap(),
    )?;
    ctx.write(
        &shielded_token_target_locked_amount_key,
        token::Amount::from_uint(1_000_000_000, IBC_TOKEN_DENOM).unwrap(),
    )?;
    ctx.write(
        &shielded_token_kp_gain_key,
        Dec::from_str("120000").unwrap(),
    )?;
    ctx.write(
        &shielded_token_kd_gain_key,
        Dec::from_str("120000").unwrap(),
    )?;
    Ok(())
}
