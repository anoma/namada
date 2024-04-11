//! A tx to initialize a new established address with a given public key and
//! a validity predicate.

use namada_tx_prelude::*;

const HASH_LEN: usize = hash::HASH_LENGTH;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let tx_data = account::InitAccount::try_from_slice(&data[..])
        .wrap_err("failed to decode InitAccount")?;
    debug_log!("apply_tx called to init a new established account");

    let vp_code_sec = signed
        .get_section(&tx_data.vp_code_hash)
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

    let entropy = {
        let mut buffer = [0u8; HASH_LEN * 2];

        // Add code hash as entropy
        buffer[..HASH_LEN].copy_from_slice(&signed.code_sechash().0);

        // Add data hash as entropy
        buffer[HASH_LEN..].copy_from_slice(&signed.data_sechash().0);

        buffer
    };

    let address =
        ctx.init_account(vp_code_sec.code.hash(), &vp_code_sec.tag, &entropy)?;

    match account::init_account(ctx, &address, tx_data) {
        Ok(address) => {
            debug_log!("Created account {}", address.encode(),)
        }
        Err(err) => {
            debug_log!("Account creation failed with: {}", err);
            panic!()
        }
    }
    Ok(())
}
