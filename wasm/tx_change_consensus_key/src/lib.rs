//! A tx for a validator to change their consensus key.

use namada_tx_prelude::transaction::pos::ConsensusKeyChange;
use namada_tx_prelude::*;

#[transaction(gas = 220000)] // TODO: need to benchmark this gas
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data")?;
    let ConsensusKeyChange {
        validator,
        consensus_key,
    } = transaction::pos::ConsensusKeyChange::try_from_slice(&data[..])
        .wrap_err("failed to decode Dec value")?;

    // Check that the tx has been signed with the new consensus key
    if !matches!(
        verify_signatures_of_pks(ctx, &signed, vec![consensus_key.clone()]),
        Ok(true)
    ) {
        debug_log!("Consensus key ownership signature verification failed");
        panic!()
    }

    ctx.change_validator_consensus_key(&validator, &consensus_key)
}
