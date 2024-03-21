//! A tx to initialize a new validator account with a given public keys and a
//! validity predicates.

use namada_tx_prelude::transaction::pos::BecomeValidator;
use namada_tx_prelude::*;

#[transaction(gas = 4395397)]
fn apply_tx(ctx: &mut Ctx, tx_data: Tx) -> TxResult {
    let signed = tx_data;
    let data = signed.data().ok_or_err_msg("Missing data").map_err(|err| {
        ctx.set_commitment_sentinel();
        err
    })?;
    let become_validator = BecomeValidator::try_from_slice(&data[..])
        .wrap_err("failed to decode InitValidator")?;
    debug_log!("apply_tx called to init a new validator account");

    // Check that the tx has been signed with all the keys to be used for the
    // validator account
    let all_pks = vec![
        become_validator.consensus_key.clone(),
        key::common::PublicKey::Secp256k1(
            become_validator.eth_cold_key.clone(),
        ),
        key::common::PublicKey::Secp256k1(become_validator.eth_hot_key.clone()),
        become_validator.protocol_key.clone(),
    ];
    if !matches!(verify_signatures_of_pks(ctx, &signed, all_pks), Ok(true)) {
        debug_log!("Keys ownership signature verification failed");
        panic!()
    }

    // Register the validator in PoS
    match ctx.become_validator(become_validator) {
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
