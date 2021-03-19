// TODO the memory types, serialization, and other "plumbing" code will be
// injected into the wasm module by the host to reduce file size
use anoma_vm_env::memory;
use borsh::{BorshDeserialize, BorshSerialize};
use core::slice;
use std::mem::{self, size_of};

/// The environment provides calls to host functions via this C interface:
extern "C" {
    // TODO storage access with e.g.
    fn read(key_ptr: *const u8, key_len: usize, result_ptr: u64) -> i32;
    fn update(key_ptr: *const u8, key_len: usize, val_ptr: *const u8, val_len: usize);
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
    let tx_data = slice.to_vec() as memory::TxData;

    // This is how reading from storage works in near:
    // - from wasm, `fn storage_read(key_len: u64, key_ptr: u64, register_id: u64)
    //   -> u64;` The wasm choose register_id and call it with this function. On
    //   success, returns 1, otherwise 0 and doesn't use the register
    //
    //         let result = storage_read(key.len() as u64, key.as_ptr() as
    // u64, 1);
    //
    // - from host, write the value into the register
    // - from wasm, allocate buffer and read from register:
    //
    //      if result == 1 {
    //         let value = [0u8; size_of::<u64>()];
    //         read_register(1, value.as_ptr() as u64);

    // we know the len from wasm, so just pre-allocate it and give it ptr
    do_apply_tx(tx_data);
}

fn do_apply_tx(_tx_data: memory::TxData) {
    // source and destination address
    let src_key = "va/balance/eth";
    let dest_key = "ba/balance/eth";
    let amount = 10;

    let bal_size = size_of::<u64>();
    let src_bal_buf: Vec<u8> = Vec::with_capacity(bal_size);
    let result = unsafe { read(src_key.as_ptr(), src_key.len(), src_bal_buf.as_ptr() as u64) };
    if result == 1 {
        let mut slice = unsafe { slice::from_raw_parts(src_bal_buf.as_ptr(), bal_size) };
        let src_bal: u64 = u64::deserialize(&mut slice).unwrap();

        let dest_bal_buf: Vec<u8> = Vec::with_capacity(bal_size);
        let result = unsafe {
            read(
                dest_key.as_ptr(),
                dest_key.len(),
                dest_bal_buf.as_ptr() as u64,
            )
        };
        if result == 1 {
            let mut slice = unsafe { slice::from_raw_parts(dest_bal_buf.as_ptr(), bal_size) };
            let dest_bal: u64 = u64::deserialize(&mut slice).unwrap();
            // TODO this doesn't work: runtime error
            // let dest_bal: u64 = u64::deserialize(&mut &dest_bal_buf[..]).unwrap();

            let src_new_bal = src_bal - amount;
            let dest_new_bal = dest_bal + amount;
            let mut src_new_bal_buf: Vec<u8> = Vec::with_capacity(8);
            src_new_bal.serialize(&mut src_new_bal_buf).unwrap();
            let mut dest_new_bal_buf: Vec<u8> = Vec::with_capacity(8);
            dest_new_bal.serialize(&mut dest_new_bal_buf).unwrap();

            unsafe {
                update(
                    src_key.as_ptr(),
                    src_key.len(),
                    src_new_bal_buf.as_ptr(),
                    src_new_bal_buf.len(),
                )
            };
            unsafe {
                update(
                    dest_key.as_ptr(),
                    dest_key.len(),
                    dest_new_bal_buf.as_ptr(),
                    dest_new_bal_buf.len(),
                )
            };
        }
    }
}
