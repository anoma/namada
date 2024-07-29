use namada_test_utils::ibc::{
    make_new_client_state_bytes, make_new_consensus_state_bytes,
};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    // This transaction will just store the IBC client state and the consensus
    // state as if the chain was upgraded
    let current_height = ctx.get_block_height()?.0;
    // Make the states with the last committed height
    let target_height = current_height - 1;
    let client_state = make_new_client_state_bytes(target_height);

    let header = ctx.get_block_header(target_height.into())?.unwrap();
    let consensus_state = make_new_consensus_state_bytes(header);

    // Need to read the upgrade state with the next height
    let upgrade_height = current_height + 1;
    let height = format!("0-{upgrade_height}").parse().unwrap();
    let upgraded_client_state_key = ibc::upgraded_client_state_key(height);
    ctx.write_bytes(&upgraded_client_state_key, client_state)?;
    let upgraded_consensus_state_key =
        ibc::upgraded_consensus_state_key(height);
    ctx.write_bytes(&upgraded_consensus_state_key, consensus_state)?;

    Ok(())
}
