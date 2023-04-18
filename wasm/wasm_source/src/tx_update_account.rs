//! A tx for updating an account's vp, threshold and associated public keys.
//! This tx wraps the validity predicate inside `SignedTxData` as
//! its input as declared in `shared` crate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let update_vp = transaction::UpdateAccount::try_from_slice(&data[..])
        .wrap_err("failed to decode UpdateVp")?;

    debug_log!("update VP for: {:#?}", update_vp.addr);

    if let Some(vp_code_hash) = update_vp.vp_code_hash {
        ctx.update_validity_predicate(&update_vp.addr, vp_code_hash)?;
    }

    if let Some(threshold) = update_vp.threshold {
        let pk_threshold = key::threshold_key(&update_vp.addr);
        ctx.write(&pk_threshold, threshold)?;
    }

    for (pk, index) in update_vp.public_keys.iter().zip(0u64..) {
        let pk_key = key::pk_key(&update_vp.addr, index);
        ctx.write(&pk_key, pk)?;
    }

    Ok(())
}
