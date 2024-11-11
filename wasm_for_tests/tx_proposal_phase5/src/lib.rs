use namada_tx_prelude::*;

pub const MIN_PROPOSAL_GRACE_EPOCHS: u64 = 8;
pub const MIN_PROPOSAL_VOTING_PERIOD: u64 = 28;

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    // 1. Enable NAM transfers
    let native_token_transferable_key =
        parameters_storage::get_native_token_transferable_key();
    ctx.write(&native_token_transferable_key, true)?;

    // 2. Update governance parameters
    let min_proposal_grace_epochs_key =
        gov_storage::keys::get_min_proposal_grace_epochs_key();
    ctx.write(&min_proposal_grace_epochs_key, MIN_PROPOSAL_GRACE_EPOCHS)?;

    let min_proposal_voting_period_key =
        gov_storage::keys::get_min_proposal_voting_period_key();
    ctx.write(&min_proposal_voting_period_key, MIN_PROPOSAL_VOTING_PERIOD)?;

    Ok(())
}
