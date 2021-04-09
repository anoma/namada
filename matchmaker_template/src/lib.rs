use anoma_vm_env::matchmaker_prelude::*;

/// The module interface callable by wasm runtime:
#[no_mangle]
pub extern "C" fn match_intent(
    intent_data_1_ptr: u64,
    intent_data_1_len: u64,
    intent_data_2_ptr: u64,
    intent_data_2_len: u64,
) -> u64 {
    let log_msg = "start matchmaker";
    unsafe {
        log_string(log_msg.as_ptr() as _, log_msg.len() as _);
    }

    let get_intent_data = |ptr, len| {
        let slice = unsafe { slice::from_raw_parts(ptr as *const u8, len as _) };
        anoma_data_template::Intent::try_from_slice(&slice).unwrap()
    };

    do_match_intent(
        get_intent_data(intent_data_1_ptr, intent_data_1_len),
        get_intent_data(intent_data_2_ptr, intent_data_2_len),
    )
}

fn do_match_intent(
    data_intent_1: anoma_data_template::Intent,
    data_intent_2: anoma_data_template::Intent,
) -> u64 {
    if data_intent_1.token_sell == data_intent_2.token_buy
        && data_intent_1.amount_sell == data_intent_2.amount_buy
        && data_intent_1.token_buy == data_intent_2.token_sell
        && data_intent_1.amount_buy == data_intent_2.amount_sell
    {
        let tx_1 = anoma_data_template::Transfer {
            source: data_intent_1.addr.clone(),
            target: data_intent_2.addr.clone(),
            token: data_intent_1.token_buy,
            amount: data_intent_1.amount_buy,
        };
        let tx_2 = anoma_data_template::Transfer {
            source: data_intent_2.addr,
            target: data_intent_1.addr,
            token: data_intent_1.token_sell,
            amount: data_intent_1.amount_sell,
        };
        let tx_data = anoma_data_template::TxData {
            transfers: vec![tx_1, tx_2],
        };

        let tx_data_bytes = tx_data.try_to_vec().unwrap();
        unsafe { send_match(tx_data_bytes.as_ptr() as _, tx_data_bytes.len() as _) };
        0
    } else {
        1
    }
}
