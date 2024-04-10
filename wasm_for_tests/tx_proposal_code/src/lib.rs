use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: Tx) -> TxResult {
    // governance
    let target_key = gov_storage::keys::get_min_proposal_grace_epochs_key();
    ctx.write(&target_key, 9_u64)?;

    // parameters
    let target_key = parameters_storage::get_vp_allowlist_storage_key();
    ctx.write(&target_key, vec!["hash"])?;
    Ok(())
}
