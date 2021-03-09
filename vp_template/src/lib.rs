use borsh::{BorshDeserialize, BorshSerialize};
use core::slice;

// TODO Plumbing functionality between the ledger and VPs will be injected into
// the wasm before it's ran (it bloats the size considerably)
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct TxMsg {
    pub src: String,
    pub dest: String,
    pub amount: u64,
}

/// The environment provides calls to host functions via this C interface:
extern "C" {}

/// The module interface callable by wasm runtime:
#[no_mangle]
pub extern "C" fn validate_tx(tx_ptr: i32, tx_len: i32) -> bool {
    let slice = unsafe { slice::from_raw_parts(tx_ptr as _, tx_len as _) };
    let tx = TxMsg::try_from_slice(slice).unwrap();
    if tx.src == "va" && tx.amount > 0 {
        true
    } else {
        false
    }
}

// pub extern "C" fn validate_intent(...) -> bool {
//     false
// }
