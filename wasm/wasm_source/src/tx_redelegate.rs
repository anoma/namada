//! A tx for a delegator (non-validator bond owner) to redelegate bonded tokens
//! from one validator to another.

use namada_tx_prelude::*;

// TODO: add to benches and find the new value
#[transaction(gas = 430000)]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data")?;
    let transaction::pos::Redelegation {
        src_validator,
        dest_validator,
        owner,
        amount,
    } = transaction::pos::Redelegation::try_from_slice(&data[..])
        .wrap_err("failed to decode a Redelegation")?;
    ctx.redelegate_tokens(&owner, &src_validator, &dest_validator, amount)
}
