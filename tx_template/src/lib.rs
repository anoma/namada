/// The environment provides calls to host functions via this C interface:
extern "C" {
    fn transfer(
        src_ptr: *const u8,
        src_len: usize,
        dest_ptr: *const u8,
        dest_len: usize,
        amount: u64,
    );
    // TODO storage access with e.g.
    // fn create(key, value);
    // fn read(key) -> value;
    // fn update(key, value);
    // fn delete(key);
    // fn iterate_prefix(key) -> iter;
    // fn iter_next(iter) -> (key, value);
}

/// The module interface callable by wasm runtime:
#[no_mangle]
pub extern "C" fn apply_tx(_tx_data_ptr: i32, _tx_data_len: i32) {
    // source and destination address
    let src = "va";
    let dest = "ba";
    let amount = 10;
    unsafe {
        transfer(src.as_ptr(), src.len(), dest.as_ptr(), dest.len(), amount);
    }
}
