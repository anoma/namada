//! A tx to vote on a proposal

use namada_tx_prelude::action::{Action, GovAction, Write};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let tx_data = governance::VoteProposalData::try_from_slice(&data[..])
        .wrap_err("Failed to decode VoteProposalData value")?;

    // The tx must be authorized by the source address
    ctx.insert_verifier(&tx_data.voter)?;

    ctx.push_action(Action::Gov(GovAction::VoteProposal {
        id: tx_data.id,
        voter: tx_data.voter.clone(),
    }))?;

    debug_log!("apply_tx called to vote a governance proposal");

    governance::vote_proposal(ctx, tx_data)
        .wrap_err("Failed to vote on governance proposal")
}
