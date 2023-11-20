//! A tx to initialize a new validator account with a given public keys and a
//! validity predicates.

use namada_tx_prelude::transaction::pos::InitValidator;
use namada_tx_prelude::*;

#[transaction(gas = 4395397)]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let init_validator = InitValidator::try_from_slice(&data[..])
        .wrap_err("failed to decode InitValidator")?;
    debug_log!("apply_tx called to init a new validator account");

    // Get the validator vp code from the extra section
    let validator_vp_code_sec = signed
        .get_section(&init_validator.validator_vp_code_hash)
        .ok_or_err_msg("validator vp section not found")
        .map_err(|err| {
            ctx.set_commitment_sentinel();
            err
        })?
        .extra_data_sec()
        .ok_or_err_msg("validator vp section must be tagged as extra")
        .map_err(|err| {
            ctx.set_commitment_sentinel();
            err
        })?;

    // Check that the tx has been signed with all the keys to be used for the
    // validator account
    let mut all_pks = init_validator.account_keys.clone();
    all_pks.push(init_validator.consensus_key.clone());
    all_pks.push(key::common::PublicKey::Secp256k1(
        init_validator.eth_cold_key.clone(),
    ));
    all_pks.push(key::common::PublicKey::Secp256k1(
        init_validator.eth_hot_key.clone(),
    ));
    all_pks.push(init_validator.protocol_key.clone());
    if !matches!(verify_signatures_of_pks(ctx, &signed, all_pks), Ok(true)) {
        debug_log!("Keys ownership signature verification failed");
        panic!()
    }

    // Register the validator in PoS
    match ctx.init_validator(
        init_validator,
        validator_vp_code_sec.code.hash(),
        &validator_vp_code_sec.tag,
    ) {
        Ok(validator_address) => {
            debug_log!("Created validator {}", validator_address.encode(),)
        }
        Err(err) => {
            debug_log!("Validator creation failed with: {}", err);
            panic!()
        }
    }
    Ok(())
}
