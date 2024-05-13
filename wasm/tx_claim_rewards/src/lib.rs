//! A tx for a user to claim PoS inflationary rewards due to bonds used as
//! voting power in consensus.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let withdraw = transaction::pos::Withdraw::try_from_slice(&data[..])
        .wrap_err("Failed to decode Withdraw value")?;

    ctx.claim_reward_tokens(withdraw.source.as_ref(), &withdraw.validator)
        .wrap_err("Failed to claim rewards")?;

    Ok(())
}
