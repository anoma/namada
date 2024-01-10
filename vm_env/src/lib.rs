//! This crate contains the WASM VM low-level interface.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

use std::mem::ManuallyDrop;

use borsh::BorshDeserialize;
use namada_core::types::internal::{HostEnvResult, KeyVal};

/// Transaction environment imports
pub mod tx {
    // These host functions are implemented in the Namada's [`host_env`]
    // module. The environment provides calls to them via this C interface.
    extern "C" {
        // Read variable-length data when we don't know the size up-front,
        // returns the size of the value (can be 0), or -1 if the key is
        // not present. If a value is found, it will be placed in the read
        // cache, because we cannot allocate a buffer for it before we know
        // its size.
        pub fn namada_tx_read(key_ptr: u64, key_len: u64) -> i64;

        // Read a value from result buffer.
        pub fn namada_tx_result_buffer(result_ptr: u64);

        // Returns 1 if the key is present, -1 otherwise.
        pub fn namada_tx_has_key(key_ptr: u64, key_len: u64) -> i64;

        // Write key/value
        pub fn namada_tx_write(
            key_ptr: u64,
            key_len: u64,
            val_ptr: u64,
            val_len: u64,
        );

        // Write a temporary key/value
        pub fn namada_tx_write_temp(
            key_ptr: u64,
            key_len: u64,
            val_ptr: u64,
            val_len: u64,
        );

        // Delete the given key and its value
        pub fn namada_tx_delete(key_ptr: u64, key_len: u64);

        // Get an ID of a data iterator with key prefix, ordered by storage
        // keys.
        pub fn namada_tx_iter_prefix(prefix_ptr: u64, prefix_len: u64) -> u64;

        // Returns the size of the value (can be 0), or -1 if there's no next
        // value. If a value is found, it will be placed in the read
        // cache, because we cannot allocate a buffer for it before we know
        // its size.
        pub fn namada_tx_iter_next(iter_id: u64) -> i64;

        // Insert a verifier
        pub fn namada_tx_insert_verifier(addr_ptr: u64, addr_len: u64);

        // Update a validity predicate
        pub fn namada_tx_update_validity_predicate(
            addr_ptr: u64,
            addr_len: u64,
            code_hash_ptr: u64,
            code_hash_len: u64,
            code_tag_ptr: u64,
            code_tag_len: u64,
        );

        // Initialize a new account
        pub fn namada_tx_init_account(
            code_hash_ptr: u64,
            code_hash_len: u64,
            code_tag_ptr: u64,
            code_tag_len: u64,
            result_ptr: u64,
        );

        // Emit an IBC event
        pub fn namada_tx_emit_ibc_event(event_ptr: u64, event_len: u64);

        // Get IBC events
        pub fn namada_tx_get_ibc_events(
            event_type_ptr: u64,
            event_type_len: u64,
        ) -> i64;

        // Get the chain ID
        pub fn namada_tx_get_chain_id(result_ptr: u64);

        // Get the current block height
        pub fn namada_tx_get_block_height() -> u64;

        // Get the current block header
        pub fn namada_tx_get_block_header(height: u64) -> i64;

        // Get the current block hash
        pub fn namada_tx_get_block_hash(result_ptr: u64);

        // Get the current block epoch
        pub fn namada_tx_get_block_epoch() -> u64;

        // Get the predecessor epochs
        pub fn namada_tx_get_pred_epochs() -> i64;

        // Get the current tx index
        pub fn namada_tx_get_tx_index() -> u32;

        // Get the native token address
        pub fn namada_tx_get_native_token(result_ptr: u64);

        // Requires a node running with "Info" log level
        pub fn namada_tx_log_string(str_ptr: u64, str_len: u64);

        /// Charge the provided amount of gas for the current tx
        pub fn namada_tx_charge_gas(used_gas: u64);

        /// Execute IBC tx.
        // Temp. workaround for <https://github.com/anoma/namada/issues/1831>
        pub fn namada_tx_ibc_execute();

        /// Set the sentinel for a wrong tx section commitment
        pub fn namada_tx_set_commitment_sentinel();

        // Verify the signatures of a tx
        pub fn namada_tx_verify_tx_section_signature(
            hash_list_ptr: u64,
            hash_list_len: u64,
            public_keys_map_ptr: u64,
            public_keys_map_len: u64,
            threshold: u8,
            max_signatures_ptr: u64,
            max_signatures_len: u64,
        ) -> i64;

        /// Update the masp note commitment tree with the new notes
        pub fn namada_tx_update_masp_note_commitment_tree(
            transaction_ptr: u64,
            transaction_len: u64,
        ) -> i64;
    }
}

/// Validity predicate environment imports
pub mod vp {
    // These host functions are implemented in the Namada's [`host_env`]
    // module. The environment provides calls to them via this C interface.
    extern "C" {
        // Read variable-length prior state when we don't know the size
        // up-front, returns the size of the value (can be 0), or -1 if
        // the key is not present. If a value is found, it will be placed in the
        // result buffer, because we cannot allocate a buffer for it before
        // we know its size.
        pub fn namada_vp_read_pre(key_ptr: u64, key_len: u64) -> i64;

        // Read variable-length posterior state when we don't know the size
        // up-front, returns the size of the value (can be 0), or -1 if
        // the key is not present. If a value is found, it will be placed in the
        // result buffer, because we cannot allocate a buffer for it before
        // we know its size.
        pub fn namada_vp_read_post(key_ptr: u64, key_len: u64) -> i64;

        // Read variable-length temporary state when we don't know the size
        // up-front, returns the size of the value (can be 0), or -1 if
        // the key is not present. If a value is found, it will be placed in the
        // result buffer, because we cannot allocate a buffer for it before
        // we know its size.
        pub fn namada_vp_read_temp(key_ptr: u64, key_len: u64) -> i64;

        // Read a value from result buffer.
        pub fn namada_vp_result_buffer(result_ptr: u64);

        // Returns 1 if the key is present in prior state, -1 otherwise.
        pub fn namada_vp_has_key_pre(key_ptr: u64, key_len: u64) -> i64;

        // Returns 1 if the key is present in posterior state, -1 otherwise.
        pub fn namada_vp_has_key_post(key_ptr: u64, key_len: u64) -> i64;

        // Get an ID of a data iterator with key prefix in prior state, ordered
        // by storage keys.
        pub fn namada_vp_iter_prefix_pre(
            prefix_ptr: u64,
            prefix_len: u64,
        ) -> u64;

        // Get an ID of a data iterator with key prefix in posterior state,
        // ordered by storage keys.
        pub fn namada_vp_iter_prefix_post(
            prefix_ptr: u64,
            prefix_len: u64,
        ) -> u64;

        // Read variable-length iterator's next value when we don't know the
        // size up-front, returns the size of the value (can be 0), or
        // -1 if the key is not present. If a value is found, it will be
        // placed in the result buffer, because we cannot allocate a
        // buffer for it before we know its size.
        pub fn namada_vp_iter_next(iter_id: u64) -> i64;

        // Get the chain ID
        pub fn namada_vp_get_chain_id(result_ptr: u64);

        // Get the current block height
        pub fn namada_vp_get_block_height() -> u64;

        // Get the current block header
        pub fn namada_vp_get_block_header(height: u64) -> i64;

        // Get the current block hash
        pub fn namada_vp_get_block_hash(result_ptr: u64);

        // Get the current tx hash
        pub fn namada_vp_get_tx_code_hash(result_ptr: u64);

        // Get the current block epoch
        pub fn namada_vp_get_block_epoch() -> u64;

        // Get the current tx index
        pub fn namada_vp_get_tx_index() -> u32;

        // Get the native token address
        pub fn namada_vp_get_native_token(result_ptr: u64);

        // Get the IBC event
        pub fn namada_vp_get_ibc_events(
            event_type_ptr: u64,
            event_type_len: u64,
        ) -> i64;

        // Requires a node running with "Info" log level
        pub fn namada_vp_log_string(str_ptr: u64, str_len: u64);

        // Verify the signatures of a tx
        pub fn namada_vp_verify_tx_section_signature(
            hash_list_ptr: u64,
            hash_list_len: u64,
            public_keys_map_ptr: u64,
            public_keys_map_len: u64,
            signer_ptr: u64,
            signer_len: u64,
            threshold: u8,
            max_signatures_ptr: u64,
            max_signatures_len: u64,
        ) -> i64;

        pub fn namada_vp_eval(
            vp_code_hash_ptr: u64,
            vp_code_hash_len: u64,
            input_data_ptr: u64,
            input_data_len: u64,
        ) -> i64;

        /// Charge the provided amount of gas for the current vp
        pub fn namada_vp_charge_gas(used_gas: u64);
    }
}

/// This function is a helper to handle the second step of reading var-len
/// values from the host.
///
/// In cases where we're reading a value from the host in the guest and
/// we don't know the byte size up-front, we have to read it in 2-steps. The
/// first step reads the value into a result buffer and returns the size (if
/// any) back to the guest, the second step reads the value from cache into a
/// pre-allocated buffer with the obtained size.
pub fn read_from_buffer(
    read_result: i64,
    result_buffer: unsafe extern "C" fn(u64),
) -> Option<Vec<u8>> {
    if HostEnvResult::is_fail(read_result) {
        None
    } else {
        let result: Vec<u8> = Vec::with_capacity(read_result as _);
        // The `result` will be dropped from the `target`, which is
        // reconstructed from the same memory
        let result = ManuallyDrop::new(result);
        let offset = result.as_slice().as_ptr() as u64;
        unsafe { result_buffer(offset) };
        let target = unsafe {
            Vec::from_raw_parts(offset as _, read_result as _, read_result as _)
        };
        Some(target)
    }
}

/// This function is a helper to handle the second step of reading var-len
/// values in a key-value pair from the host.
pub fn read_key_val_bytes_from_buffer(
    read_result: i64,
    result_buffer: unsafe extern "C" fn(u64),
) -> Option<(String, Vec<u8>)> {
    let key_val = read_from_buffer(read_result, result_buffer)
        .and_then(|t| KeyVal::try_from_slice(&t[..]).ok());
    key_val.map(|key_val| (key_val.key, key_val.val))
}
