// TODO the memory types, serialization, and other "plumbing" code will be
// injected into the wasm module by the host to reduce file size
use anoma_vm_env::memory;
use borsh::BorshDeserialize;
use core::slice;

/// The environment provides calls to host functions via this C interface:
extern "C" {
    // NOTE: Just for testing
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
pub extern "C" fn apply_tx(tx_data_ptr: *const u8, tx_data_len: usize) {
    let slice = unsafe { slice::from_raw_parts(tx_data_ptr, tx_data_len) };
    let tx_data = memory::TxDataIn::try_from_slice(slice).unwrap();

    do_apply_tx(tx_data);
}

fn do_apply_tx(_tx_data: memory::TxDataIn) {
    // source and destination address
    let src = "va";
    let dest = "ba";
    let amount = 10;
    do_transfer(src, dest, amount);
}

fn do_transfer(src: &str, dest: &str, amount: u64) {
    unsafe {
        transfer(src.as_ptr(), src.len(), dest.as_ptr(), dest.len(), amount);
    }
}
