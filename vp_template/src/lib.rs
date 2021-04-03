// TODO the memory types, serialization, and other "plumbing" code will be
// injected into the wasm module by the host to reduce file size
use anoma_vm_env::memory;
use borsh::BorshDeserialize;
use core::slice;
use std::mem::size_of;

/// The environment provides calls to host functions via this C interface:
extern "C" {
    // Read fixed-length prior state, returns 1 if the key is present, 0 otherwise.
    fn read_pre(key_ptr: u64, key_len: u64, result_ptr: u64) -> u64;

    // Read variable-length prior state when we don't know the size up-front,
    // returns the size of the value (can be 0), or -1 if the key is not
    // present.
    fn read_pre_varlen(key_ptr: u64, key_len: u64, result_ptr: u64) -> i64;

    // Read fixed-length posterior state, returns 1 if the key is present, 0
    // otherwise.
    fn read_post(key_ptr: u64, key_len: u64, result_ptr: u64) -> u64;

    // Read variable-length posterior state when we don't know the size up-front,
    // returns the size of the value (can be 0), or -1 if the key is not
    // present.
    fn read_post_varlen(key_ptr: u64, key_len: u64, result_ptr: u64) -> i64;

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

fn do_validate_tx(_tx_data: memory::TxData, _addr: &str, keys_changed: Vec<String>) -> bool {
    for key in keys_changed.iter() {
        let pre_buf: Vec<u8> = Vec::with_capacity(0);
        let pre_len =
            unsafe { read_pre_varlen(key.as_ptr() as _, key.len() as _, pre_buf.as_ptr() as _) };

        let post_ptr = pre_len;
        let post_len =
            unsafe { read_post_varlen(key.as_ptr() as _, key.len() as _, post_ptr as _) };

        if pre_len == -1 || post_len == -1 {
            let log_msg = format!(
                "something went wrong fro key: {}, pre: {}, post: {}",
                key, pre_len, post_len
            );
            unsafe {
                log_string(log_msg.as_ptr() as _, log_msg.len() as _);
            }
        } else {
            let pre = unsafe { slice::from_raw_parts(pre_buf.as_ptr(), pre_len as _) };
            let post = unsafe { slice::from_raw_parts(post_ptr as *const u8, post_len as _) };

            let log_msg = format!(
                "validate_tx key: {}, pre: {:#?}, post: {:#?}",
                key, pre, post,
            );
            unsafe {
                log_string(log_msg.as_ptr() as _, log_msg.len() as _);
            }
        }
    }
    true
}
