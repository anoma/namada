use std::str::FromStr;

use dec::Dec;
use namada_tx_prelude::*;
use token::storage_key::balance_key;

pub type Denomination = u8;
pub type ChannelId = &'static str;
pub type BaseToken = &'static str;

pub type TokenMaxReward = &'static str;
pub type TokenTargetLockedAmount = u64;
pub type KpGain = &'static str;
pub type KdGain = &'static str;

const IBC_TOKENS: [(
    Denomination,
    ChannelId,
    BaseToken,
    TokenMaxReward,
    TokenTargetLockedAmount,
    KpGain,
    KdGain,
); 1] = [(
    0,
    "channel-0",
    "samoleans",
    "1.0",
    1_000_000_000,
    "120000",
    "120000",
)];

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    // Read the current MASP token map
    let token_map_key = token::storage_key::masp_token_map_key();
    let mut token_map = ctx
        .read::<masp::TokenMap>(&token_map_key)?
        .unwrap_or_default();

    // Enable shielded set rewards for ibc tokens
    for (
        denomination,
        channel_id,
        base_token,
        max_reward,
        target_locked_amount,
        kp,
        kd,
    ) in IBC_TOKENS
    {
        let ibc_denom = format!("transfer/{channel_id}/{base_token}");
        let token_address = ibc::ibc_token(&ibc_denom);

        let shielded_token_last_inflation_key =
            token::storage_key::masp_last_inflation_key(&token_address);
        let shielded_token_last_locked_amount_key =
            token::storage_key::masp_last_locked_amount_key(&token_address);
        let shielded_token_max_rewards_key =
            token::storage_key::masp_max_reward_rate_key(&token_address);
        let shielded_token_target_locked_amount_key =
            token::storage_key::masp_locked_amount_target_key(&token_address);
        let shielded_token_kp_gain_key =
            token::storage_key::masp_kp_gain_key(&token_address);
        let shielded_token_kd_gain_key =
            token::storage_key::masp_kd_gain_key(&token_address);

        // Add the ibc token to the masp token map
        token_map.insert(ibc_denom, token_address.clone());

        // Read the current balance of the IBC token in MASP and set that as
        // initial locked amount
        let ibc_balance_key = balance_key(
            &token_address,
            &Address::Internal(address::InternalAddress::Masp),
        );
        let current_ibc_amount =
            ctx.read::<token::Amount>(&ibc_balance_key)?.unwrap();
        ctx.write(&shielded_token_last_locked_amount_key, current_ibc_amount)?;

        // Initialize the remaining MASP inflation keys
        ctx.write(&shielded_token_last_inflation_key, token::Amount::zero())?;

        ctx.write(
            &shielded_token_max_rewards_key,
            Dec::from_str(max_reward).unwrap(),
        )?;
        ctx.write(
            &shielded_token_target_locked_amount_key,
            token::Amount::from_uint(target_locked_amount, denomination)
                .unwrap(),
        )?;
        ctx.write(&shielded_token_kp_gain_key, Dec::from_str(kp).unwrap())?;
        ctx.write(&shielded_token_kd_gain_key, Dec::from_str(kd).unwrap())?;
    }

    // Write the token map back to storage
    ctx.write(&token_map_key, token_map)?;

    Ok(())
}
