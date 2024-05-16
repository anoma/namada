use namada_tx_prelude::*;

/// A tx that endlessly charges gas from the host environment
#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    let target_key = parameters_storage::get_tx_allowlist_storage_key();
    loop {
        // NOTE: don't propagate the error to verify that execution abortion
        // is done in host and does not require guest cooperation
        let _ = ctx.write(&target_key, vec!["hash"]);
    }
}
