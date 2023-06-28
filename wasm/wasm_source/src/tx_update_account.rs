//! A tx for updating an account's validity predicate.
//! This tx wraps the validity predicate inside `SignedTxData` as
//! its input as declared in `shared` crate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data")?;
    let update_vp = transaction::account::UpdateVp::try_from_slice(&data[..])
        .wrap_err("failed to decode UpdateVp")?;

    debug_log!("update VP for: {:#?}", update_vp.addr);

    if let Some(hash) = update_vp.vp_code_hash {
        let vp_code_hash = signed
            .get_section(&hash)
            .ok_or_err_msg("vp code section not found")?
            .extra_data_sec()
            .ok_or_err_msg("vp code section must be tagged as extra")?
            .code
            .hash();

        ctx.update_validity_predicate(&update_vp.addr, vp_code_hash)?;
    }

    if let Some(threshold) = update_vp.threshold {
        let threshold_key = key::threshold_key(&update_vp.addr);
        ctx.write(&threshold_key, threshold)?;
    }

    if !update_vp.public_keys.is_empty() {}

    Ok(())
}
