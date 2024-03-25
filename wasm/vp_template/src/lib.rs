use namada_vp_prelude::*;

#[validity_predicate(gas = 1000)]
fn validate_tx(
    ctx: &Ctx,
    tx_data: Tx,
    addr: Address,
    keys_changed: BTreeSet<storage::Key>,
    verifiers: BTreeSet<Address>,
) -> VpResult {
    log_string(format!(
        "validate_tx called with addr: {}, key_changed: {:#?}, tx_data: \
         {:#?}, verifiers: {:?}",
        addr, keys_changed, tx_data, verifiers
    ));

    for key in keys_changed {
        let pre: Option<u64> = ctx.read_pre(&key).into_vp_error()?;
        let post: Option<u64> = ctx.read_post(&key).into_vp_error()?;
        log_string(format!(
            "validate_tx key: {}, pre: {:#?}, post: {:#?}",
            key, pre, post,
        ));
    }
    accept()
}
