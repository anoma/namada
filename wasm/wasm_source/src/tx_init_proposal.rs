//! A tx to create a governance proposal.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx: Tx) -> TxResult {
    let data = tx.data().ok_or_err_msg("Missing data")?;
    let tx_data =
        transaction::governance::InitProposalData::try_from_slice(&data[..])
        .wrap_err("failed to decode InitProposalData")?;
    let content = tx
        .get_section(&tx_data.content)
        .ok_or_err_msg("Missing content")?
        .extra_data()
        .ok_or_err_msg("Missing full content")?;
    log_string("apply_tx called to create a new governance proposal");

    governance::init_proposal(ctx, tx_data, content)
}
