//! A tx for a user to claim PoS inflationary rewards due to bonds used as
//! voting power in consensus.

use namada_tx_prelude::*;

#[transaction(gas = 260000)] // TODO: needs to be benchmarked
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data")?;
    let withdraw = transaction::pos::Withdraw::try_from_slice(&data[..])
        .wrap_err("failed to decode Withdraw")?;

    ctx.claim_reward_tokens(withdraw.source.as_ref(), &withdraw.validator)?;
    Ok(())
}
