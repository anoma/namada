use anoma_data_template::*;
use anoma_vm_env::{matchmaker, matchmaker_prelude::*};

matchmaker! {
    fn match_intent(intent_1: Intent, intent_2: Intent) -> bool {
        log_string(format!("match_intent\nintent_1: {:#?}\nintent_2: {:#?}", intent_1, intent_2));

        if intent_1.token_sell == intent_2.token_buy
            && intent_1.amount_sell == intent_2.amount_buy
            && intent_1.token_buy == intent_2.token_sell
            && intent_1.amount_buy == intent_2.amount_sell
        {
            let tx_1 = Transfer {
                source: intent_1.addr.clone(),
                target: intent_2.addr.clone(),
                token: intent_1.token_buy,
                amount: intent_1.amount_buy,
            };
            let tx_2 = Transfer {
                source: intent_2.addr,
                target: intent_1.addr,
                token: intent_1.token_sell,
                amount: intent_1.amount_sell,
            };
            let tx_data = TxData {
                transfers: vec![tx_1, tx_2],
            };

            send_match(tx_data);
            true
        } else {
            false
        }
    }
}
