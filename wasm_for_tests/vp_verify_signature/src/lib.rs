use namada_vp_prelude::*;

#[validity_predicate]
fn validate_tx(
    ctx: &Ctx,
    tx_data: BatchedTx,
    addr: Address,
    _keys_changed: BTreeSet<storage::Key>,
    _verifiers: BTreeSet<Address>,
) -> VpResult {
    let mut gadget = VerifySigGadget::new();
    gadget.verify_signatures(ctx, &tx_data.tx, &tx_data.cmt, &addr)
}
