//! A tx to vote on a proposal

use namada_tx_prelude::action::{Action, GovAction, Write};
use namada_tx_prelude::proof_of_stake::{
    find_delegation_validators, is_validator,
};
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

    let voting_end_epoch_key =
        gov_storage::keys::get_voting_end_epoch_key(tx_data.id);
    let end_epoch = if let Some(epoch) = ctx.read(&voting_end_epoch_key)? {
        epoch
    } else {
        return Err(Error::new_alloc(format!(
            "Proposal id {} doesn't exist.",
            tx_data.id
        )));
    };

    // Pass in all target validators to the proposal vote. Whether or not the
    // vote will be counted based on the validator state will be determined
    // when tallying the votes and executing the proposal.
    let is_validator = is_validator(ctx, &tx_data.voter).unwrap_or(false);
    let delegation_targets = if !is_validator {
        find_delegation_validators(ctx, &tx_data.voter, &end_epoch)?
    } else {
        [tx_data.voter.clone()].into()
    };

    governance::vote_proposal(ctx, tx_data, delegation_targets)
        .wrap_err("Failed to vote on governance proposal")
}
