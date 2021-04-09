use anoma_data_template::*;
use anoma_vm_env::{matchmaker, matchmaker_prelude::*};

matchmaker! {
    fn match_intent(data_intent_1: Intent, data_intent_2: Intent) -> bool {
        if data_intent_1.token_sell == data_intent_2.token_buy
            && data_intent_1.amount_sell == data_intent_2.amount_buy
            && data_intent_1.token_buy == data_intent_2.token_sell
            && data_intent_1.amount_buy == data_intent_2.amount_sell
        {
            let tx_1 = Transfer {
                source: data_intent_1.addr.clone(),
                target: data_intent_2.addr.clone(),
                token: data_intent_1.token_buy,
                amount: data_intent_1.amount_buy,
            };
            let tx_2 = Transfer {
                source: data_intent_2.addr,
                target: data_intent_1.addr,
                token: data_intent_1.token_sell,
                amount: data_intent_1.amount_sell,
            };
            let tx_data = TxData {
                transfers: vec![tx_1, tx_2],
            };

            let tx_data_bytes = tx_data.try_to_vec().unwrap();
            unsafe { send_match(tx_data_bytes.as_ptr() as _, tx_data_bytes.len() as _) };
            true
        } else {
            false
        }
    }
}
