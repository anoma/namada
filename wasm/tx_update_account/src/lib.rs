//! A tx for updating an account's validity predicate.
//! This tx wraps the validity predicate inside `SignedTxData` as
//! its input as declared in `namada` crate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, batched_tx: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&batched_tx)?;
    let tx_data = account::UpdateAccount::try_from_slice(&data[..])
        .wrap_err("Failed to decode UpdateAccount tx data")?;

    let owner = &tx_data.addr;
    debug_log!("update VP for: {:#?}", tx_data.addr);

    // The tx must be authorized by the source address
    ctx.insert_verifier(owner)?;

    if let Some(hash) = tx_data.vp_code_hash {
        let vp_code_sec = batched_tx
            .tx
            .get_section(&hash)
            .ok_or_err_msg("VP code section not found")
            .map_err(|err| {
                ctx.set_commitment_sentinel();
                err
            })?
            .extra_data_sec()
            .ok_or_err_msg("VP code section must be tagged as extra")
            .map_err(|err| {
                ctx.set_commitment_sentinel();
                err
            })?;

        ctx.update_validity_predicate(
            owner,
            vp_code_sec.code.hash(),
            &vp_code_sec.tag,
        )
        .wrap_err("Failed to update the account's validity predicate")?;
    }

    if let Some(threshold) = tx_data.threshold {
        let threshold_key = account::threshold_key(owner);
        ctx.write(&threshold_key, threshold)
            .wrap_err("Failed to update the account's signing threshold")?;
    }

    if !tx_data.public_keys.is_empty() {
        account::clear_public_keys(ctx, owner)
            .wrap_err("Failed to reset the account's public keys")?;
        for (index, public_key) in tx_data.public_keys.iter().enumerate() {
            let index = index as u8;
            account::pks_handle(owner)
                .insert(ctx, index, public_key.clone())
                .wrap_err("Failed to update the public keys of the account")?;
        }
    }

    Ok(())
}
