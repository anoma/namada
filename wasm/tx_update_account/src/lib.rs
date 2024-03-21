//! A tx for updating an account's validity predicate.
//! This tx wraps the validity predicate inside `SignedTxData` as
//! its input as declared in `namada` crate.

use namada_tx_prelude::*;

#[transaction(gas = 968137)]
fn apply_tx(ctx: &mut Ctx, tx: Tx) -> TxResult {
    let signed = tx;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let tx_data = account::UpdateAccount::try_from_slice(&data[..])
        .wrap_err("failed to decode UpdateAccount")?;

    let owner = &tx_data.addr;
    debug_log!("update VP for: {:#?}", tx_data.addr);

    if let Some(hash) = tx_data.vp_code_hash {
        let vp_code_sec = signed
            .get_section(&hash)
            .ok_or_err_msg("vp code section not found")
            .map_err(|err| {
                ctx.set_commitment_sentinel();
                err
            })?
            .extra_data_sec()
            .ok_or_err_msg("vp code section must be tagged as extra")
            .map_err(|err| {
                ctx.set_commitment_sentinel();
                err
            })?;

        ctx.update_validity_predicate(
            owner,
            vp_code_sec.code.hash(),
            &vp_code_sec.tag,
        )?;
    }

    if let Some(threshold) = tx_data.threshold {
        let threshold_key = account::threshold_key(owner);
        ctx.write(&threshold_key, threshold)?;
    }

    if !tx_data.public_keys.is_empty() {
        account::clear_public_keys(ctx, owner)?;
        for (index, public_key) in tx_data.public_keys.iter().enumerate() {
            let index = index as u8;
            account::pks_handle(owner).insert(
                ctx,
                index,
                public_key.clone(),
            )?;
        }
    }

    Ok(())
}
