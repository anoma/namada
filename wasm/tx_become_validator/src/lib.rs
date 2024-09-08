//! A tx to initialize a new validator account with a given public keys and a
//! validity predicates.

use booleans::ResultBoolExt;
use namada_tx_prelude::data::pos::BecomeValidator;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let become_validator = BecomeValidator::try_from_slice(&data[..])
        .wrap_err("Failed to decode BecomeValidator tx data")?;
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
    verify_signatures_of_pks(&tx_data.tx, all_pks).true_or_else(|| {
        const ERR_MSG: &str = "Keys ownership signature verification failed";
        debug_log!("{ERR_MSG}");
        Error::new_const(ERR_MSG)
    })?;

    // Register the validator in PoS
    let validator_address = ctx
        .become_validator(become_validator)
        .wrap_err("Validator creation failed")?;

    debug_log!("Created validator {validator_address}");
    Ok(())
}
