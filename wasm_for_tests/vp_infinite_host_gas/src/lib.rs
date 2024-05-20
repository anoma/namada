use namada_vp_prelude::*;

/// A vp that endlessly charges gas from the host environment
#[validity_predicate]
fn validate_tx(
    ctx: &Ctx,
    _tx_data: BatchedTx,
    _addr: Address,
    _keys_changed: BTreeSet<storage::Key>,
    _verifiers: BTreeSet<Address>,
) -> VpResult {
    let target_key =
        namada_tx_prelude::parameters_storage::get_tx_allowlist_storage_key();
    loop {
        // NOTE: don't propagate the error to verify that execution abortion
        // is done in host and does not require guest cooperation
        let _ = ctx.read_bytes_pre(&target_key);
    }
}
