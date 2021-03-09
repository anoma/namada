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
pub extern "C" fn validate_tx(tx_ptr: *const u8, tx_len: usize) -> bool {
    // TODO more plumbing here
    let slice = unsafe { slice::from_raw_parts(tx_ptr, tx_len) };
    let tx = TxMsg::try_from_slice(slice).unwrap();

    // run validation with the concrete type(s)
    do_validate_tx(tx)
}

fn do_validate_tx(tx: TxMsg) -> bool {
    if tx.amount > 0
    // && tx.src == "va"
    {
        true
    } else {
        false
    }
}

// pub extern "C" fn validate_intent(...) -> bool {
//     false
// }
