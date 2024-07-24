use namada_test_utils::ibc::{
    make_new_client_state_bytes, make_new_consensus_state_bytes,
};
use namada_tx_prelude::*;

const UPGRADE_HEIGHT: u64 = 680;

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    // This transaction will just store the IBC client state and the consensus
    // state as if the chain was upgraded
    let chain_id = ctx.get_chain_id()?;
    let client_state = make_new_client_state_bytes(chain_id, UPGRADE_HEIGHT);
    log_string("made the client state");

    let height = ctx.get_block_height();
    log_string(format!("current height: {height:?}"));
    let header = ctx.get_block_header(UPGRADE_HEIGHT.into())?.unwrap();
    log_string("got the header");
    let consensus_state = make_new_consensus_state_bytes(header);
    log_string("made the consensus state");

    let height = format!("0-{UPGRADE_HEIGHT}").parse().unwrap();
    let upgraded_client_state_key = ibc::upgraded_client_state_key(height);
    ctx.write_bytes(&upgraded_client_state_key, client_state)?;
    let upgraded_consensus_state_key =
        ibc::upgraded_consensus_state_key(height);
    ctx.write_bytes(&upgraded_consensus_state_key, consensus_state)?;

    Ok(())
}
