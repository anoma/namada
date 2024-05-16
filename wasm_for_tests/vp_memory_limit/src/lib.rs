use namada_vp_prelude::*;

#[validity_predicate]
fn validate_tx(
    _ctx: &Ctx,
    tx_data: BatchedTx,
    _addr: Address,
    _keys_changed: BTreeSet<storage::Key>,
    _verifiers: BTreeSet<Address>,
) -> VpResult {
    let BatchedTx {
        tx: tx_data,
        ref cmt,
    } = tx_data;
    let len = usize::try_from_slice(&tx_data.data(cmt).as_ref().unwrap()[..])
        .unwrap();
    log_string(format!("allocate len {}", len));
    let bytes: Vec<u8> = vec![6_u8; len];
    // use the variable to prevent it from compiler optimizing it away
    log_string(format!("{:?}", &bytes[..8]));
    accept()
}
