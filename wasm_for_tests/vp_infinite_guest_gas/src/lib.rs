use namada_vp_prelude::*;

/// A vp that endlessly charges gas from the guest environment
#[validity_predicate]
fn validate_tx(
    _ctx: &Ctx,
    _tx_data: BatchedTx,
    _addr: Address,
    _keys_changed: BTreeSet<storage::Key>,
    _verifiers: BTreeSet<Address>,
) -> VpResult {
    #[allow(clippy::empty_loop)]
    loop {}
}
