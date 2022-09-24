//! A tx to initialize a new validator account and staking reward account with a
//! given public keys and a validity predicates.

use namada_tx_prelude::transaction::InitValidator;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let init_validator = InitValidator::try_from_slice(&data[..])
        .wrap_err("failed to decode InitValidator")?;
    debug_log!("apply_tx called to init a new validator account");

    // Register the validator in PoS
    match ctx.init_validator(init_validator) {
        Ok((validator_address)) => {
            debug_log!(
                "Created validator {}",
                validator_address.encode(),
            )
        }
        Err(err) => {
            debug_log!("Validator creation failed with: {}", err);
            panic!()
        }
    }
    Ok(())
}
