/// Transaction environment imports
pub mod tx {
    pub use anoma_data_template;
    pub use borsh::{BorshDeserialize, BorshSerialize};
    pub use core::slice;
    pub use std::mem::size_of;

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
    pub use anoma_data_template;
    pub use borsh::{BorshDeserialize, BorshSerialize};
    pub use core::slice;
    pub use std::mem::size_of;

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
    pub use anoma_data_template;
    pub use borsh::{BorshDeserialize, BorshSerialize};
    pub use core::slice;

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
