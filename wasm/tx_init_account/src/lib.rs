//! A tx to initialize a new established address with a given public key and
//! a validity predicate.

use namada_tx_prelude::*;

const HASH_LEN: usize = hash::HASH_LENGTH;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let BatchedTx {
        tx: signed,
        ref cmt,
    } = tx_data;
    let tx_data = account::InitAccount::try_from_slice(&data[..])
        .wrap_err("Failed to decode InitAccount tx data")?;
    debug_log!("apply_tx called to init a new established account");

    let vp_code_sec = signed
        .get_section(&tx_data.vp_code_hash)
        .ok_or_err_msg("VP code section not found in tx")
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

    let entropy = {
        let mut buffer = [0u8; HASH_LEN * 2];

        // Add code hash as entropy
        buffer[..HASH_LEN].copy_from_slice(&cmt.code_sechash().0);

        // Add data hash as entropy
        buffer[HASH_LEN..].copy_from_slice(&cmt.data_sechash().0);

        buffer
    };

    let address = ctx
        .init_account(vp_code_sec.code.hash(), &vp_code_sec.tag, &entropy)
        .wrap_err("Failed to generate a new established account address")?;

    account::init_account(ctx, &address, tx_data)
        .wrap_err("Account creation failed")?;

    debug_log!("Created account {address}");
    Ok(())
}
