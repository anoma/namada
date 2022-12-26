//! A tx for token withdrawal from a testnet faucet account.
//! This tx uses `faucet_pow::Solution` wrapped inside `SignedTxData`
//! as its input.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let solution = faucet_pow::Solution::try_from_slice(&data[..])
        .wrap_err("failed to decode faucet_pow::Solution")?;
    debug_log!(
        "tx_testnet_faucet_withdrawal called with solution: {:#?}",
        solution
    );
    // Apply the solution to prevent replay
    solution.apply_from_tx(ctx)?;

    // Apply the transfer
    let token::Transfer {
        source,
        target,
        token,
        sub_prefix,
        amount,
        key,
        shielded,
    } = solution.challenge.transfer;
    token::transfer(
        ctx, &source, &target, &token, sub_prefix, amount, &key, &shielded,
    )
}
