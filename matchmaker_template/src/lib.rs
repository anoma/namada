use anoma_vm_env::{
    matchmaker,
    matchmaker_prelude::{
        intent::{Intent, IntentTransfers},
        key::ed25519::Signed,
        *,
    },
};

matchmaker! {
    fn match_intent(intent_1: Vec<u8>, intent_2: Vec<u8>) -> bool {
        let intent_1 = decode_intent_data(intent_1);
        let intent_2 = decode_intent_data(intent_2);
        log_string(format!("match_intent\nintent_1: {:#?}\nintent_2: {:#?}", intent_1, intent_2));

        if intent_1.data.token_sell == intent_2.data.token_buy
            && intent_1.data.amount_sell == intent_2.data.amount_buy
            && intent_1.data.token_buy == intent_2.data.token_sell
            && intent_1.data.amount_buy == intent_2.data.amount_sell
        {
            let transfer_1 = token::Transfer {
                source: intent_1.data.addr.clone(),
                target: intent_2.data.addr.clone(),
                token: intent_1.data.token_sell.clone(),
                amount: intent_1.data.amount_sell.clone(),
            };
            let transfer_2 = token::Transfer {
                source: intent_2.data.addr.clone(),
                target: intent_1.data.addr.clone(),
                token: intent_1.data.token_buy.clone(),
                amount: intent_1.data.amount_buy.clone(),
            };
            let tx_data = IntentTransfers {
                intent_1,
                transfer_1,
                intent_2,
                transfer_2,
            };

            let tx_data_bytes = tx_data.try_to_vec().unwrap();
            send_match(tx_data_bytes);
            true
        } else {
            false
        }
    }
}

fn decode_intent_data(bytes: Vec<u8>) -> Signed<Intent> {
    Signed::<Intent>::try_from_slice(&bytes[..]).unwrap()
}
