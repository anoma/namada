/// The environment provides calls to host functions via this C interface:
extern "C" {}

/// The module interface callable by wasm runtime:
#[no_mangle]
pub extern "C" fn validate_tx(
    state_before_ptr: i32,
    state_before_len: i32,
    state_after_ptr: i32,
    state_after_len: i32,
    tx_ptr: i32,
    tx_len: i32,
) -> bool {
    true
}

// pub extern "C" fn validate_intent(...) -> bool {
//     false
// }
