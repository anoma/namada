use namada_vp_prelude::*;

#[validity_predicate(gas = 1000)]
fn validate_tx(
    _ctx: &Ctx,
    _tx_data: Tx,
    _addr: Address,
    _keys_changed: BTreeSet<storage::Key>,
    _verifiers: BTreeSet<Address>,
) -> VpResult {
    accept()
}
