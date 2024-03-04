//! A tx to vote on a proposal

use namada_tx_prelude::*;

#[transaction(gas = 840866)]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let tx_data = governance::VoteProposalData::try_from_slice(&data[..])
        .wrap_err("failed to decode VoteProposalData")?;

    debug_log!("apply_tx called to vote a governance proposal");

    governance::vote_proposal(ctx, tx_data)
}
