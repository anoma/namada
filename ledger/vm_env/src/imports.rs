/// Transaction environment imports
pub mod tx {
    pub use borsh::{BorshDeserialize, BorshSerialize};
    pub use core::slice;
    pub use std::mem::size_of;
    use crate::memory::{KeyVal, KeyValIterator};
    use std::marker::PhantomData;

    /// This macro expects a function with signature:
    ///
    /// ```
    /// fn apply_tx(tx_data: memory::Data)
    /// ```
    /// TODO try to switch to procedural macros instead
    #[macro_export]
    macro_rules! transaction {
        (fn $fn:ident ( $($arg:ident : $type:ty),* $(,)?) $body:block ) => {
            fn $fn( $($arg: $type),* ) $body

            // The module entrypoint callable by wasm runtime
            #[no_mangle]
            extern "C" fn _apply_tx(tx_data_ptr: u64, tx_data_len: u64) {
                let slice = unsafe {
                    slice::from_raw_parts(
                        tx_data_ptr as *const u8,
                        tx_data_len as _,
                    )
                };
                let tx_data = slice.to_vec() as memory::Data;

                $fn(tx_data);
            }
        }
    }

    /// Try to read a fixed-length value at the given key from storage.
    pub fn read<K: AsRef<str>, T: BorshDeserialize>(key: K) -> Option<T> {
        let key = key.as_ref();
        let size = size_of::<T>();
        let result = Vec::with_capacity(size);
        let found = unsafe {
            _read(key.as_ptr() as _, key.len() as _, result.as_ptr() as _)
        };
        if found == 0 {
            None
        } else {
            let slice = unsafe { slice::from_raw_parts(result.as_ptr(), size) };
            T::try_from_slice(slice).ok()
        }
    }

    /// Try to read a variable-length value at the given key from storage.
    pub fn read_varlen<K: AsRef<str>, T: BorshDeserialize>(
        key: K,
    ) -> Option<T> {
        let key = key.as_ref();
        let size = size_of::<T>();
        let result = Vec::with_capacity(size);
        let found = unsafe {
            _read_varlen(
                key.as_ptr() as _,
                key.len() as _,
                result.as_ptr() as _,
            )
        };
        if found == -1 {
            None
        } else {
            let slice =
                unsafe { slice::from_raw_parts(result.as_ptr(), found as _) };
            T::try_from_slice(slice).ok()
        }
    }

    /// Write a value at the given key to storage.
    pub fn write<K: AsRef<str>, T: BorshSerialize>(key: K, val: T) {
        let key = key.as_ref();
        let mut buf: Vec<u8> = Vec::with_capacity(size_of::<T>());
        val.serialize(&mut buf).unwrap();
        unsafe {
            _write(
                key.as_ptr() as _,
                key.len() as _,
                buf.as_ptr() as _,
                buf.len() as _,
            )
        };
    }

    /// Delete a value at the given key from storage.
    pub fn delete<K: AsRef<str>, T: BorshSerialize>(key: K) {
        let key = key.as_ref();
        unsafe { _delete(key.as_ptr() as _, key.len() as _) };
    }

    /// Get an iterator with the given prefix
    pub fn iter_prefix<K: AsRef<str>, T: BorshDeserialize>(prefix: K) -> KeyValIterator<T> {
        let prefix = prefix.as_ref();
        let iter_id = unsafe {
            _iter_prefix(prefix.as_ptr() as _, prefix.len() as _)
        };
        KeyValIterator(iter_id, PhantomData)
    }

    impl<T: BorshDeserialize> Iterator for KeyValIterator<T> {
        type Item = (String, T);

        fn next(&mut self) -> Option<(String, T)> {
            let result: Vec<u8> = Vec::with_capacity(0);
            let size = unsafe {
                _iter_next_varlen(self.0, result.as_ptr() as _)
            };
            if size == -1 {
                None
            } else {
                let slice = unsafe { slice::from_raw_parts(result.as_ptr(), size as _) };
                match KeyVal::try_from_slice(slice) {
                    Ok(key_val) => {
                        match T::try_from_slice(&key_val.val) {
                            Ok(v) => Some((key_val.key, v)),
                            Err(_) => None
                        }
                    }
                    Err(_) => None
                }
            }
        }
    }

    /// Insert a verifier
    pub fn insert_verifier<A: AsRef<str>>(addr: A) {
        let addr = addr.as_ref();
        unsafe {
            _insert_verifier(addr.as_ptr() as _, addr.len() as _)
        }
    }

    /// Log a string. The message will be printed at the [`log::Level::Info`].
    pub fn log_string<T: AsRef<str>>(msg: T) {
        let msg = msg.as_ref();
        unsafe {
            _log_string(msg.as_ptr() as _, msg.len() as _);
        }
    }

    /// These host functions are implemented in the Anoma's [`host_env`]
    /// module. The environment provides calls to them via this C interface.
    extern "C" {
        // Read fixed-length data, returns 1 if the key is present, 0 otherwise.
        fn _read(key_ptr: u64, key_len: u64, result_ptr: u64) -> u64;

        // Read variable-length data when we don't know the size up-front,
        // returns the size of the value (can be 0), or -1 if the key is
        // not present.
        fn _read_varlen(key_ptr: u64, key_len: u64, result_ptr: u64) -> i64;

        // Write key/value, returns 1 on success, 0 otherwise.
        fn _write(key_ptr: u64, key_len: u64, val_ptr: u64, val_len: u64);

        // Delete the given key and its value, returns 1 on success, 0
        // otherwise.
        fn _delete(key_ptr: u64, key_len: u64) -> u64;

        // Get an ID of a data iterator with key prefix
        fn _iter_prefix(prefix_ptr: u64, prefix_len: u64) -> u64;

        // Read data from the specified iterator, returns 1 if it exists,
        // 0 otherwise.
        fn _iter_next(iter_id: u64, result_ptr: u64) -> u64;

        // Read variable-length data when we don't know the size up-front,
        // returns the size of the value (can be 0), or -1 if the key is not
        // present.
        fn _iter_next_varlen(iter_id: u64, result_ptr: u64) -> i64;

        // Insert a verifier
        fn _insert_verifier(addr_ptr: u64, addr_len: u64);

        // Requires a node running with "Info" log level
        fn _log_string(str_ptr: u64, str_len: u64);
    }
}

/// Validity predicate environment imports
pub mod vp {
    pub use borsh::{BorshDeserialize, BorshSerialize};
    pub use core::slice;
    pub use std::mem::size_of;
    use crate::memory::{KeyVal, PostKeyValIterator, PreKeyValIterator};
    use std::marker::PhantomData;

    /// This macro expects a function with signature:
    ///
    /// ```
    /// fn validate_tx(tx_data: memory::Data, addr: &str, keys_changed: Vec<String>) -> bool
    /// ```
    #[macro_export]
    macro_rules! validity_predicate {
        (fn $fn:ident ( $($arg:ident : $type:ty),* $(,)?) -> $ret:ty $body:block ) => {
            fn $fn( $($arg: $type),* ) -> $ret $body

            // The module entrypoint callable by wasm runtime
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
                verifiers_ptr: u64,
                verifiers_len: u64,
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

                let slice = unsafe {
                    slice::from_raw_parts(
                        verifiers_ptr as *const u8,
                        verifiers_len as _,
                    )
                };
                let verifiers: HashSet<String> = HashSet::try_from_slice(slice).unwrap();

                // run validation with the concrete type(s)
                if $fn(tx_data, addr, keys_changed, verifiers) {
                    1
                } else {
                    0
                }
            }
        }
    }

    /// Try to read a fixed-length value at the given key from storage before
    /// transaction execution.
    pub fn read_pre<K: AsRef<str>, T: BorshDeserialize>(key: K) -> Option<T> {
        let key = key.as_ref();
        let size = size_of::<T>();
        let result = Vec::with_capacity(size);
        let found = unsafe {
            _read_pre(key.as_ptr() as _, key.len() as _, result.as_ptr() as _)
        };
        if found == 0 {
            None
        } else {
            let slice = unsafe { slice::from_raw_parts(result.as_ptr(), size) };
            T::try_from_slice(slice).ok()
        }
    }

    /// Try to read a fixed-length value at the given key from storage after
    /// transaction execution.
    pub fn read_post<K: AsRef<str>, T: BorshDeserialize>(key: K) -> Option<T> {
        let key = key.as_ref();
        let size = size_of::<T>();
        let result = Vec::with_capacity(size);
        let found = unsafe {
            _read_post(key.as_ptr() as _, key.len() as _, result.as_ptr() as _)
        };
        if found == 0 {
            None
        } else {
            let slice = unsafe { slice::from_raw_parts(result.as_ptr(), size) };
            T::try_from_slice(slice).ok()
        }
    }

    /// Try to read a variable-length value at the given key from storage before
    /// transaction execution.
    pub fn read_pre_varlen<K: AsRef<str>, T: BorshDeserialize>(
        key: K,
    ) -> Option<T> {
        let key = key.as_ref();
        let size = size_of::<T>();
        let result = Vec::with_capacity(size);
        let found = unsafe {
            _read_pre_varlen(
                key.as_ptr() as _,
                key.len() as _,
                result.as_ptr() as _,
            )
        };
        if found == -1 {
            None
        } else {
            let slice =
                unsafe { slice::from_raw_parts(result.as_ptr(), found as _) };
            T::try_from_slice(slice).ok()
        }
    }

    /// Try to read a variable-length value at the given key from storage after
    /// transaction execution.
    pub fn read_post_varlen<K: AsRef<str>, T: BorshDeserialize>(
        key: K,
    ) -> Option<T> {
        let key = key.as_ref();
        let size = size_of::<T>();
        let result = Vec::with_capacity(size);
        let found = unsafe {
            _read_post_varlen(
                key.as_ptr() as _,
                key.len() as _,
                result.as_ptr() as _,
            )
        };
        if found == -1 {
            None
        } else {
            let slice =
                unsafe { slice::from_raw_parts(result.as_ptr(), found as _) };
            T::try_from_slice(slice).ok()
        }
    }

    /// Get an iterator with the given prefix before transaction execution
    pub fn iter_prefix_pre<K: AsRef<str>, T: BorshDeserialize>(prefix: K) -> PreKeyValIterator<T> {
        let prefix = prefix.as_ref();
        let iter_id = unsafe {
            _iter_prefix(prefix.as_ptr() as _, prefix.len() as _)
        };
        PreKeyValIterator(iter_id, PhantomData)
    }

    impl<T: BorshDeserialize> Iterator for PreKeyValIterator<T> {
        type Item = (String, T);

        fn next(&mut self) -> Option<(String, T)> {
            let result: Vec<u8> = Vec::with_capacity(0);
            let size = unsafe {
                _iter_pre_next_varlen(self.0, result.as_ptr() as _)
            };
            if size == -1 {
                None
            } else {
                let slice = unsafe { slice::from_raw_parts(result.as_ptr(), size as _) };
                match KeyVal::try_from_slice(slice) {
                    Ok(key_val) => {
                        match T::try_from_slice(&key_val.val) {
                            Ok(v) => Some((key_val.key, v)),
                            Err(_) => None
                        }
                    }
                    Err(_) => None
                }
            }
        }
    }

    /// Get an iterator with the given prefix after transaction execution
    pub fn iter_prefix_post<K: AsRef<str>, T: BorshDeserialize>(prefix: K) -> PostKeyValIterator<T> {
        let prefix = prefix.as_ref();
        let iter_id = unsafe {
            _iter_prefix(prefix.as_ptr() as _, prefix.len() as _)
        };
        PostKeyValIterator(iter_id, PhantomData)
    }

    impl<T: BorshDeserialize> Iterator for PostKeyValIterator<T> {
        type Item = (String, T);

        fn next(&mut self) -> Option<(String, T)> {
            let result: Vec<u8> = Vec::with_capacity(0);
            let size = unsafe {
                _iter_post_next_varlen(self.0, result.as_ptr() as _)
            };
            if size == -1 {
                None
            } else {
                let slice = unsafe { slice::from_raw_parts(result.as_ptr(), size as _) };
                match KeyVal::try_from_slice(slice) {
                    Ok(key_val) => {
                        match T::try_from_slice(&key_val.val) {
                            Ok(v) => Some((key_val.key, v)),
                            Err(_) => None
                        }
                    }
                    Err(_) => None
                }
            }
        }
    }

    /// Log a string. The message will be printed at the [`log::Level::Info`].
    pub fn log_string<T: AsRef<str>>(msg: T) {
        let msg = msg.as_ref();
        unsafe {
            _log_string(msg.as_ptr() as _, msg.len() as _);
        }
    }

    /// These host functions are implemented in the Anoma's [`host_env`]
    /// module. The environment provides calls to them via this C interface.
    extern "C" {
        // Read fixed-length prior state, returns 1 if the key is present, 0
        // otherwise.
        fn _read_pre(key_ptr: u64, key_len: u64, result_ptr: u64) -> u64;

        // Read variable-length prior state when we don't know the size
        // up-front, returns the size of the value (can be 0), or -1 if
        // the key is not present.
        fn _read_pre_varlen(key_ptr: u64, key_len: u64, result_ptr: u64)
            -> i64;

        // Read fixed-length posterior state, returns 1 if the key is present, 0
        // otherwise.
        fn _read_post(key_ptr: u64, key_len: u64, result_ptr: u64) -> u64;

        // Read variable-length posterior state when we don't know the size
        // up-front, returns the size of the value (can be 0), or -1 if
        // the key is not present.
        fn _read_post_varlen(
            key_ptr: u64,
            key_len: u64,
            result_ptr: u64,
        ) -> i64;

        // Get an ID of a data iterator with key prefix
        fn _iter_prefix(prefix_ptr: u64, prefix_len: u64) -> u64;

        // Read data from the specified iterator, returns 1 if it exists,
        // 0 otherwise.
        fn _iter_pre_next(iter_id: u64, result_ptr: u64) -> u64;

        // Read variable-length prior state when we don't know the size up-front,
        // returns the size of the value (can be 0), or -1 if the key is not
        // present.
        fn _iter_pre_next_varlen(iter_id: u64, result_ptr: u64) -> i64;

        // Read data from the specified iterator, returns 1 if it exists,
        // 0 otherwise.
        fn _iter_post_next(iter_id: u64, result_ptr: u64) -> u64;

        // Read variable-length posterior state when we don't know the size
        // up-front, returns the size of the value (can be 0), or -1 if the
        // key is not present.
        fn _iter_post_next_varlen(iter_id: u64, result_ptr: u64) -> i64;

        // Requires a node running with "Info" log level
        fn _log_string(str_ptr: u64, str_len: u64);
    }
}

/// Matchmaker environment imports
pub mod matchmaker {
    pub use borsh::{BorshDeserialize, BorshSerialize};
    pub use core::slice;
    use std::mem::size_of;

    /// This macro expects a function with signature:
    ///
    /// ```
    /// fn match_intent(intent_1: Intent, intent_2: Intent) -> bool
    /// ```
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
                let get_intent_data = |ptr, len| {
                    let slice = unsafe {
                        slice::from_raw_parts(ptr as *const u8, len as _)
                    };
                    slice.to_vec()
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

    /// Try to read a fixed-length value at the given key from the ledger.
    pub fn read<K: AsRef<str>, T: BorshDeserialize>(key: K) -> Option<T> {
        let key = key.as_ref();
        let size = size_of::<T>();
        let result = Vec::with_capacity(size);
        let found = unsafe {
            _read(key.as_ptr() as _, key.len() as _, result.as_ptr() as _)
        };
        if found == 0 {
            None
        } else {
            let slice = unsafe { slice::from_raw_parts(result.as_ptr(), size) };
            T::try_from_slice(slice).ok()
        }
    }

    pub fn send_match(tx_data: Vec<u8>) {
        unsafe { _send_match(tx_data.as_ptr() as _, tx_data.len() as _) };
    }

    /// Log a string. The message will be printed at the [`log::Level::Info`].
    pub fn log_string<T: AsRef<str>>(msg: T) {
        let msg = msg.as_ref();
        unsafe {
            _log_string(msg.as_ptr() as _, msg.len() as _);
        }
    }

    /// These host functions are implemented in the Anoma's [`host_env`]
    /// module. The environment provides calls to them via this C interface.
    extern "C" {
        // Read fixed-length data, returns 1 if the key is present, 0 otherwise.
        pub fn _read(key_ptr: u64, key_len: u64, result_ptr: u64) -> u64;

        pub fn _send_match(data_ptr: u64, data_len: u64);

        // Requires a node running with "Info" log level
        pub fn _log_string(str_ptr: u64, str_len: u64);
    }
}
