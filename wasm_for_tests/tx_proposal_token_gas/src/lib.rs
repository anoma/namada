use std::collections::BTreeMap;

use namada_tx_prelude::{
    parameters_storage::get_gas_cost_key, token::Amount, *,
};

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    let ibc_token = ibc::ibc_token("transfer/channel-0/samoleans");

    let gas_cost_key = get_gas_cost_key();
    let mut minimum_gas_price: BTreeMap<Address, Amount> =
        ctx.read(&gas_cost_key)?.unwrap_or_default();
    minimum_gas_price.insert(ibc_token, 1.into());
    ctx.write(&gas_cost_key, minimum_gas_price)?;

    Ok(())
}
