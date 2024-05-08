//! A tx to vote on a proposal

use namada_tx_prelude::action::{Action, GovAction, Write};
use namada_tx_prelude::proof_of_stake::find_delegation_validators;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let tx_data = governance::VoteProposalData::try_from_slice(&data[..])
        .wrap_err("Failed to decode VoteProposalData value")?;

    // The tx must be authorized by the source address
    ctx.insert_verifier(&tx_data.voter)?;

    ctx.push_action(Action::Gov(GovAction::VoteProposal {
        id: tx_data.id,
        voter: tx_data.voter.clone(),
    }))?;

    debug_log!("apply_tx called to vote a governance proposal");

    // Pass in all target validators to the proposal vote. Whether or not the
    // vote will be counted based on the validator state will be determined
    // when tallying the votes and executing the proposal.
    let current_epoch = ctx.get_block_epoch()?;
    let delegation_targets =
        find_delegation_validators(ctx, &tx_data.voter, &current_epoch)?;

    governance::vote_proposal(ctx, tx_data, delegation_targets)
        .wrap_err("Failed to vote on governance proposal")
}
