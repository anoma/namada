use anoma_data_template::*;
use anoma_vm_env::{filter, filter_prelude::*};

filter! {
    fn validate_intent(intent: Vec<u8>) -> bool {
        let intent = decode_intent_data(intent);
        if intent.is_some() {
            log_string(format!(r#"intent {:#?} is valid"#, intent));
            true
        }
        else {false}
    }
}

fn decode_intent_data(bytes: Vec<u8>) -> Option<Intent> {
    anoma_data_template::Intent::try_from_slice(&bytes[..]).ok()
}
