// TODO the memory types, serialization, and other "plumbing" code will be
// injected into the wasm module by the host to reduce file size
use anoma_vm_env::memory;
use borsh::BorshDeserialize;
use core::slice;

/// The environment provides calls to host functions via this C interface:
extern "C" {
    // Requires a node running with "Info" log level
    fn log_string(str_ptr: u64, str_len: u64);
}

/// The module interface callable by wasm runtime:
#[no_mangle]
pub extern "C" fn validate_tx(
    // VP's account's address
    // TODO Should the address be on demand (a call to host function?)
    addr_ptr: u64,
    addr_len: u64,
    tx_data_ptr: u64,
    tx_data_len: u64,
    keys_changed_ptr: u64,
    keys_changed_len: u64,
) -> u64 {
    // TODO more plumbing here
    let slice = unsafe { slice::from_raw_parts(addr_ptr as *const u8, addr_len as _) };
    let addr = core::str::from_utf8(slice).unwrap();

    let slice = unsafe { slice::from_raw_parts(tx_data_ptr as *const u8, tx_data_len as _) };
    let tx_data = slice.to_vec() as memory::TxData;

    let slice =
        unsafe { slice::from_raw_parts(keys_changed_ptr as *const u8, keys_changed_len as _) };
    let keys_changed: Vec<String> = Vec::try_from_slice(slice).unwrap();

    let log_msg = format!(
        "validate_tx called with addr: {}, key_changed: {:#?}, tx_data: {:#?}",
        addr, keys_changed, tx_data
    );
    unsafe {
        log_string(log_msg.as_ptr() as _, log_msg.len() as _);
    }

    // run validation with the concrete type(s)
    if do_validate_tx(tx_data, addr, keys_changed) {
        1
    } else {
        0
    }
}

fn do_validate_tx(_tx_data: memory::TxData, _addr: &str, _keys_changed: Vec<String>) -> bool {
    // if tx.amount > 0
    // // && tx.src == "va"
    // {
    //     true
    // } else {
    //     false
    // }
    true
}
