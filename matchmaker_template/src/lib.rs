// TODO the memory types, serialization, and other "plumbing" code will be
// injected into the wasm module by the host to reduce file size

use anoma_vm_env::memory;
use borsh::{BorshDeserialize, BorshSerialize};
use core::slice;

/// The environment provides calls to host functions via this C interface:
extern "C" {

    // Read fixed-length data, returns 1 if the key is present, 0 otherwise.
    fn read(key_ptr: u64, key_len: u64, result_ptr: u64) -> u64;

    fn send_match(data_ptr:u64, data_len:u64);

    // Requires a node running with "Info" log level
    fn log_string(str_ptr: u64, str_len: u64);

}

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
        data_types::IntentData::try_from_slice(&slice).unwrap()
    };

    do_match_intent(
        get_intent_data(intent_data_1_ptr, intent_data_1_len),
        get_intent_data(intent_data_2_ptr, intent_data_2_len),
    )
}

fn do_match_intent(
    data_intent_1: data_types::IntentData,
    data_intent_2: data_types::IntentData,
) -> u64 {
    if data_intent_1.token_sell == data_intent_2.token_buy
        && data_intent_1.amount_sell == data_intent_2.amount_buy
        && data_intent_1.token_buy == data_intent_2.token_sell
        && data_intent_1.amount_buy == data_intent_2.amount_sell
    {
        let tx_data = data_types::TxDataExchange {
            addr_a: data_intent_1.addr,
            addr_b: data_intent_2.addr,
            token_a_b: data_intent_1.token_sell,
            amount_a_b: data_intent_1.amount_sell,
            token_b_a: data_intent_1.token_buy,
            amount_b_a: data_intent_1.amount_buy,
        };
        println!("in matchmaker : found match {:?} ", tx_data);

        let tx_data_bytes = tx_data.try_to_vec().unwrap();
        unsafe { send_match(tx_data_bytes.as_ptr() as _ , tx_data_bytes.len() as _ ) };
        0
    } else {
        1
    }
}
