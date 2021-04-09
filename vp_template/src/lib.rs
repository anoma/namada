use anoma_data_template::*;
use anoma_vm_env::{validity_predicate, vp_prelude::*};

validity_predicate! {
    fn validate_tx(_tx_data: memory::Data, _addr: &str, keys_changed: Vec<String>) -> bool {
        for key in keys_changed.iter() {
            let pre_buf: Vec<u8> = Vec::with_capacity(0);
            let pre_len = unsafe {
                read_pre_varlen(key.as_ptr() as _, key.len() as _, pre_buf.as_ptr() as _)
            };

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
}
