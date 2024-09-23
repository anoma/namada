use namada_vp_prelude::*;

#[validity_predicate]
fn validate_tx(
    ctx: &Ctx,
    tx_data: BatchedTx,
    _addr: Address,
    _keys_changed: BTreeSet<storage::Key>,
    _verifiers: BTreeSet<Address>,
) -> VpResult {
    use namada_tx_prelude::transaction::eval_vp::EvalVp;
    let EvalVp {
        vp_code_hash,
        input,
    }: EvalVp =
        EvalVp::try_from_slice(&tx_data.to_ref().data().as_ref().unwrap()[..])
            .unwrap();
    ctx.eval(vp_code_hash, input.to_ref()).into_vp_error()
}
