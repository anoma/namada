/// The environment provides calls to host functions via this C interface:
extern "C" {
    // NOTE: Just for testing
    fn transfer(
        src_ptr: *const u8,
        src_len: usize,
        dest_ptr: *const u8,
        dest_len: usize,
        token_ptr: *const u8,
        token_len: usize,
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
pub extern "C" fn apply_tx_from_intent(_tx_data_ptr: i32, _tx_data_len: i32) {
    // source and destination address
    let addr_a = String::from("va");
    let addr_b = String::from("ba");
    let token_a_b = String::from("eth");
    let amount_a_b = 80;
    let token_b_a = String::from("xtz");
    let amount_b_a = 10;
    unsafe {
        transfer(
            addr_a.as_ptr(),
            addr_a.len(),
            addr_b.as_ptr(),
            addr_b.len(),
            token_a_b.as_ptr(),
            token_a_b.len(),
            amount_a_b,
        );
        transfer(
            addr_b.as_ptr(),
            addr_b.len(),
            addr_a.as_ptr(),
            addr_a.len(),
            token_b_a.as_ptr(),
            token_b_a.len(),
            amount_b_a,
        );
    }
}
