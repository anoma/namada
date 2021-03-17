// TODO the memory types, serialization, and other "plumbing" code will be
// injected into the wasm module by the host to reduce file size
use anoma_vm_env::memory;
use borsh::BorshDeserialize;
use core::slice;

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
    let tx_data = slice.to_vec() as memory::TxData;
    let slice = unsafe { slice::from_raw_parts(write_log_ptr, write_log_len) };
    let write_log = memory::WriteLog::try_from_slice(slice).unwrap();

    // run validation with the concrete type(s)
    do_validate_tx(tx_data, write_log)
}

fn do_validate_tx(_tx_data: memory::TxData, _write_log: memory::WriteLog) -> bool {
    // if tx.amount > 0
    // // && tx.src == "va"
    // {
    //     true
    // } else {
    //     false
    // }
    true
}
