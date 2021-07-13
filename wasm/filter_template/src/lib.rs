use anoma_vm_env::filter_prelude::intent::FungibleTokenIntent;
use anoma_vm_env::filter_prelude::*;

#[filter]
fn validate_intent(intent: Vec<u8>) -> bool {
    // TODO: check if signature is valid
    let intent = decode_intent_data(intent);
    if intent.is_some() {
        log_string(format!(r#"intent {:#?} is valid"#, intent));
        true
    } else {
        false
    }
}

fn decode_intent_data(bytes: Vec<u8>) -> Option<FungibleTokenIntent> {
    FungibleTokenIntent::try_from_slice(&bytes[..]).ok()
}
