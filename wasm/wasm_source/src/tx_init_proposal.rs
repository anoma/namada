//! A tx to create a governance proposal.

use namada_tx_prelude::*;

#[transaction(gas = 969395)]
fn apply_tx(ctx: &mut Ctx, tx: Tx) -> TxResult {
    let data = tx.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let tx_data = governance::InitProposalData::try_from_slice(&data[..])
        .wrap_err("failed to decode InitProposalData")?;

    // Get the content from the referred to section
    let content = tx
        .get_section(&tx_data.content)
        .ok_or_err_msg("Missing proposal content")
        .map_err(|err| {
            ctx.set_commitment_sentinel();
            err
        })?
        .extra_data()
        .ok_or_err_msg("Missing full proposal content")
        .map_err(|err| {
            ctx.set_commitment_sentinel();
            err
        })?;

    // Get the code from the referred to section
    let code_hash = tx_data.get_section_code_hash();
    let code = match code_hash {
        Some(hash) => Some(
            tx.get_section(&hash)
                .ok_or_err_msg("Missing proposal code")
                .map_err(|err| {
                    ctx.set_commitment_sentinel();
                    err
                })?
                .extra_data()
                .ok_or_err_msg("Missing full proposal code")
                .map_err(|err| {
                    ctx.set_commitment_sentinel();
                    err
                })?,
        ),
        None => None,
    };

    log_string("apply_tx called to create a new governance proposal");

    governance::init_proposal(ctx, tx_data, content, code)
}
