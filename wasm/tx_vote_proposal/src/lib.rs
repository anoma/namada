//! A tx to vote on a proposal

use namada_tx_prelude::action::{Action, GovAction, Write};
use namada_tx_prelude::gov_storage::keys::get_voting_start_epoch_key;
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

    let voting_start_epoch_key = get_voting_start_epoch_key(tx_data.id);
    let proposal_start_epoch = ctx.read(&voting_start_epoch_key)?;
    let proposal_start_epoch = if let Some(epoch) = proposal_start_epoch {
        epoch
    } else {
        return Err(Error::new_alloc(format!(
            "Proposal id {} doesn't have a start epoch",
            tx_data.id
        )));
    };

    debug_log!("apply_tx called to vote a governance proposal");

    let delegations_targets =
        find_delegation_validators(ctx, &tx_data.voter, &proposal_start_epoch)?;

    governance::vote_proposal(ctx, tx_data, active_delegations_targets)
        .wrap_err("Failed to vote on governance proposal")
}
