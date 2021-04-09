use anoma_vm_env::vp_prelude::*;

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
    let tx_data = slice.to_vec() as memory::Data;

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

fn do_validate_tx(_tx_data: memory::Data, _addr: &str, keys_changed: Vec<String>) -> bool {
    for key in keys_changed.iter() {
        let pre_buf: Vec<u8> = Vec::with_capacity(0);
        let pre_len =
            unsafe { read_pre_varlen(key.as_ptr() as _, key.len() as _, pre_buf.as_ptr() as _) };

        let pre: Option<&[u8]>;
        let post_ptr: i64;
        if pre_len == -1 {
            pre = None;
            // There was no `pre` value, we can read the `post` into the same address
            post_ptr = pre_buf.as_ptr() as _;
        } else {
            pre = Some(unsafe { slice::from_raw_parts(pre_buf.as_ptr(), pre_len as _) });
            // There was a `pre` value, offset read of the `post` at its length
            post_ptr = pre_len;
        }

        let post_len =
            unsafe { read_post_varlen(key.as_ptr() as _, key.len() as _, post_ptr as _) };

        let post: Option<&[u8]>;
        if post_len == -1 {
            post = None;
        } else {
            post = Some(unsafe { slice::from_raw_parts(post_ptr as _, post_len as _) });
        }

        let log_msg = format!(
            "validate_tx key: {}, pre: {:#?}, post: {:#?}",
            key, pre, post,
        );
        unsafe {
            log_string(log_msg.as_ptr() as _, log_msg.len() as _);
        }
    }
    true
}
