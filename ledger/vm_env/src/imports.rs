/// Transaction environment imports
pub mod tx {
    pub use borsh::{BorshDeserialize, BorshSerialize};
    pub use core::slice;
    pub use std::mem::size_of;

    #[macro_export]
    macro_rules! transaction {
        (fn $fn:ident ( $($arg:ident : $type:ty),* $(,)?) $body:block ) => {
            fn $fn( $($arg: $type),* ) $body

            // The module interface callable by wasm runtime
            #[no_mangle]
            extern "C" fn _apply_tx(tx_data_ptr: u64, tx_data_len: u64) {
                let slice = unsafe {
                    slice::from_raw_parts(
                        tx_data_ptr as *const u8,
                        tx_data_len as _,
                    )
                };
                let tx_data = slice.to_vec() as memory::Data;

                let log_msg =
                    format!("apply_tx called with tx_data: {:#?}", tx_data);
                unsafe {
                    log_string(log_msg.as_ptr() as _, log_msg.len() as _);
                }

                $fn(tx_data);
            }
        }
    }

    // TODO temporarily public
    /// The environment provides calls to host functions via this C interface:
    extern "C" {
        // Read fixed-length data, returns 1 if the key is present, 0 otherwise.
        pub fn read(key_ptr: u64, key_len: u64, result_ptr: u64) -> u64;

        // Read variable-length data when we don't know the size up-front,
        // returns the size of the value (can be 0), or -1 if the key is
        // not present.
        pub fn read_varlen(key_ptr: u64, key_len: u64, result_ptr: u64) -> i64;

        // Write key/value, returns 1 on success, 0 otherwise.
        pub fn write(
            key_ptr: u64,
            key_len: u64,
            val_ptr: u64,
            val_len: u64,
        ) -> u64;

        // Delete the given key and its value, returns 1 on success, 0
        // otherwise.
        pub fn delete(key_ptr: u64, key_len: u64) -> u64;

        // Requires a node running with "Info" log level
        pub fn log_string(str_ptr: u64, str_len: u64);

        // fn iterate_prefix(key) -> iter;
        // fn iter_next(iter) -> (key, value);
    }
}

/// Validity predicate environment imports
pub mod vp {
    pub use borsh::{BorshDeserialize, BorshSerialize};
    pub use core::slice;
    pub use std::mem::size_of;

    #[macro_export]
    macro_rules! validity_predicate {
        (fn $fn:ident ( $($arg:ident : $type:ty),* $(,)?) -> $ret:ty $body:block ) => {
            fn $fn( $($arg: $type),* ) -> $ret $body

            // The module interface callable by wasm runtime
            #[no_mangle]
            extern "C" fn _validate_tx(
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
                let slice = unsafe {
                    slice::from_raw_parts(addr_ptr as *const u8, addr_len as _)
                };
                let addr = core::str::from_utf8(slice).unwrap();

                let slice = unsafe {
                    slice::from_raw_parts(
                        tx_data_ptr as *const u8,
                        tx_data_len as _,
                    )
                };
                let tx_data = slice.to_vec() as memory::Data;

                let slice = unsafe {
                    slice::from_raw_parts(
                        keys_changed_ptr as *const u8,
                        keys_changed_len as _,
                    )
                };
                let keys_changed: Vec<String> = Vec::try_from_slice(slice).unwrap();

                let log_msg = format!(
                    "validate_tx called with addr: {}, key_changed: {:#?}, tx_data: {:#?}",
                    addr, keys_changed, tx_data
                );
                unsafe {
                    log_string(log_msg.as_ptr() as _, log_msg.len() as _);
                }

                // run validation with the concrete type(s)
                if $fn(tx_data, addr, keys_changed) {
                    1
                } else {
                    0
                }
            }
        }
    }

    // TODO temporarily public
    /// The environment provides calls to host functions via this C interface:
    extern "C" {
        // Read fixed-length prior state, returns 1 if the key is present, 0
        // otherwise.
        pub fn read_pre(key_ptr: u64, key_len: u64, result_ptr: u64) -> u64;

        // Read variable-length prior state when we don't know the size
        // up-front, returns the size of the value (can be 0), or -1 if
        // the key is not present.
        pub fn read_pre_varlen(
            key_ptr: u64,
            key_len: u64,
            result_ptr: u64,
        ) -> i64;

        // Read fixed-length posterior state, returns 1 if the key is present, 0
        // otherwise.
        pub fn read_post(key_ptr: u64, key_len: u64, result_ptr: u64) -> u64;

        // Read variable-length posterior state when we don't know the size
        // up-front, returns the size of the value (can be 0), or -1 if
        // the key is not present.
        pub fn read_post_varlen(
            key_ptr: u64,
            key_len: u64,
            result_ptr: u64,
        ) -> i64;

        // Requires a node running with "Info" log level
        pub fn log_string(str_ptr: u64, str_len: u64);
    }
}

/// Matchmaker environment imports
pub mod matchmaker {
    pub use borsh::{BorshDeserialize, BorshSerialize};
    pub use core::slice;

    #[macro_export]
    macro_rules! matchmaker {
        (fn $fn:ident ( $($arg:ident : $type:ty),* $(,)?) -> $ret:ty $body:block ) => {
            fn $fn( $($arg: $type),* ) -> $ret $body

            /// The module interface callable by wasm runtime
            #[no_mangle]
            extern "C" fn _match_intent(
                intent_data_1_ptr: u64,
                intent_data_1_len: u64,
                intent_data_2_ptr: u64,
                intent_data_2_len: u64,
            ) -> u64 {
                let log_msg = "start matchmaker";
                unsafe {
                    log_string(log_msg.as_ptr() as _, log_msg.len() as _);
                }

                let get_intent_data = |ptr, len| {
                    let slice = unsafe {
                        slice::from_raw_parts(ptr as *const u8, len as _)
                    };
                    anoma_data_template::Intent::try_from_slice(&slice).unwrap()
                };

                if $fn(
                    get_intent_data(intent_data_1_ptr, intent_data_1_len),
                    get_intent_data(intent_data_2_ptr, intent_data_2_len),
                ) {
                    0
                } else {
                    1
                }
            }
        }
    }

    // TODO temporarily public
    /// The environment provides calls to host functions via this C interface:
    extern "C" {
        // Read fixed-length data, returns 1 if the key is present, 0 otherwise.
        pub fn read(key_ptr: u64, key_len: u64, result_ptr: u64) -> u64;

        pub fn send_match(data_ptr: u64, data_len: u64);

        // Requires a node running with "Info" log level
        pub fn log_string(str_ptr: u64, str_len: u64);
    }
}
