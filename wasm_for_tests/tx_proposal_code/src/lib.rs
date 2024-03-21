use namada_tx_prelude::*;

#[transaction(gas = 1000)]
fn apply_tx(ctx: &mut Ctx, _tx_data: Tx) -> TxResult {
    // governance
    let target_key = gov_storage::keys::get_min_proposal_grace_epoch_key();
    ctx.write(&target_key, 9_u64)?;

    // parameters
    let target_key = parameters_storage::get_tx_allowlist_storage_key();
    ctx.write(&target_key, vec!["hash"])?;
    Ok(())
}