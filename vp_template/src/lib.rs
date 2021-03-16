use anoma_vm_env::memory;
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
pub extern "C" fn validate_tx(
    tx_data_ptr: *const u8,
    tx_data_len: usize,
    write_log_ptr: *const u8,
    write_log_len: usize,
) -> bool {
    // TODO more plumbing here
    let slice = unsafe { slice::from_raw_parts(tx_data_ptr, tx_data_len) };
    let tx_data = memory::TxDataIn::try_from_slice(slice).unwrap();
    let slice = unsafe { slice::from_raw_parts(write_log_ptr, write_log_len) };
    let write_log = memory::WriteLogIn::try_from_slice(slice).unwrap();

    // run validation with the concrete type(s)
    do_validate_tx(tx_data, write_log)
}

fn do_validate_tx(tx_data: memory::TxDataIn, write_log: memory::WriteLogIn) -> bool {
    // if tx.amount > 0
    // // && tx.src == "va"
    // {
    //     true
    // } else {
    //     false
    // }
    true
}
