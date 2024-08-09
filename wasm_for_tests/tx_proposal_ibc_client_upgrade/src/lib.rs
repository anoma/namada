use namada_test_utils::ibc::{
    make_new_client_state_bytes, make_new_consensus_state_bytes,
};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    // This transaction will just store the IBC client state and the consensus
    // state as if the chain was upgraded
    let current_height = ctx.get_block_height()?.0;
    // Make the states based on the last committed height
    let last_committed_height = current_height - 1;
    // Need to read the upgrade state with the next height
    let upgrade_height = current_height + 1;
    // The height of the new client state is the next after the upgrade
    let height_after_upgrade = upgrade_height + 1;
    let client_state = make_new_client_state_bytes(height_after_upgrade);

    let header = ctx.get_block_header(last_committed_height.into())?.unwrap();
    let consensus_state = make_new_consensus_state_bytes(header);

    let height = format!("0-{upgrade_height}").parse().unwrap();
    let upgraded_client_state_key = ibc::upgraded_client_state_key(height);
    ctx.write_bytes(&upgraded_client_state_key, client_state)?;
    let upgraded_consensus_state_key =
        ibc::upgraded_consensus_state_key(height);
    ctx.write_bytes(&upgraded_consensus_state_key, consensus_state)?;

    Ok(())
}
