//! A tx to initialize a new validator account with a given public keys and a
//! validity predicates.

use namada_tx_prelude::transaction::InitValidator;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data")?;
    let init_validator = InitValidator::try_from_slice(&data[..])
        .wrap_err("failed to decode InitValidator")?;
    debug_log!("apply_tx called to init a new validator account");

    // Get the validator vp code from the extra section
    let validator_vp_code = signed
        .get_section(&init_validator.validator_vp_code)
        .ok_or_err_msg("validator vp section not found")?
        .extra_data()
        .ok_or_err_msg("validator vp section must be tagged as extra")?
        .data;
    // Register the validator in PoS
    match ctx.init_validator(
        init_validator,
        validator_vp_code,
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
