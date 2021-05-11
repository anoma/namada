/// Transaction environment imports
pub mod tx {
    pub use core::slice;
    use std::convert::TryFrom;
    use std::marker::PhantomData;
    pub use std::mem::size_of;

    use anoma_shared::types::{
        Address, BlockHash, BlockHeight, BLOCK_HASH_LENGTH, CHAIN_ID_LENGTH,
    };
    use anoma_shared::vm_memory::KeyVal;
    pub use borsh::{BorshDeserialize, BorshSerialize};

    /// This macro expects a function with signature:
    ///
    /// ```ignore
    /// fn apply_tx(tx_data: vm_memory::Data)
    /// ```
    /// TODO try to switch to procedural macros instead
    #[macro_export]
    macro_rules! transaction {
        (fn $fn:ident ( $($arg:ident : $type:ty),* $(,)?) $body:block ) => {
            use wee_alloc;

            // Use `wee_alloc` as the global allocator.
            #[global_allocator]
            static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

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
                let tx_data = slice.to_vec() as vm_memory::Data;

                $fn(tx_data);
            }
        }
    }

    pub struct KeyValIterator<T>(pub u64, pub PhantomData<T>);

    impl<T: BorshDeserialize> Iterator for KeyValIterator<T> {
        type Item = (String, T);

        fn next(&mut self) -> Option<(String, T)> {
            let result: Vec<u8> = Vec::with_capacity(0);
            let size = unsafe { _iter_next(self.0, result.as_ptr() as _) };
            if size == -1 {
                None
            } else {
                let slice = unsafe {
                    slice::from_raw_parts(result.as_ptr(), size as _)
                };
                match KeyVal::try_from_slice(slice) {
                    Ok(key_val) => match T::try_from_slice(&key_val.val) {
                        Ok(v) => Some((key_val.key, v)),
                        Err(_) => None,
                    },
                    Err(_) => None,
                }
            }
        }
    }

    /// Try to read a variable-length value at the given key from storage.
    pub fn read<K: AsRef<str>, T: BorshDeserialize>(key: K) -> Option<T> {
        let key = key.as_ref();
        let size = size_of::<T>();
        let result = Vec::with_capacity(size);
        let size = unsafe {
            _read(key.as_ptr() as _, key.len() as _, result.as_ptr() as _)
        };
        if size == -1 {
            None
        } else {
            let slice =
                unsafe { slice::from_raw_parts(result.as_ptr(), size as _) };
            T::try_from_slice(slice).ok()
        }
    }

    /// Check if the given key is present in storage.
    pub fn has_key(key: impl AsRef<str>) -> bool {
        let key = key.as_ref();
        let found = unsafe { _has_key(key.as_ptr() as _, key.len() as _) };
        found == 1
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
    pub fn iter_prefix<K: AsRef<str>, T: BorshDeserialize>(
        prefix: K,
    ) -> KeyValIterator<T> {
        let prefix = prefix.as_ref();
        let iter_id =
            unsafe { _iter_prefix(prefix.as_ptr() as _, prefix.len() as _) };
        KeyValIterator(iter_id, PhantomData)
    }

    /// Insert a verifier
    pub fn insert_verifier(addr: Address) {
        let addr = addr.encode();
        unsafe { _insert_verifier(addr.as_ptr() as _, addr.len() as _) }
    }

    /// Update a validity predicate
    pub fn update_validity_predicate(addr: Address, code: impl AsRef<[u8]>) {
        let addr = addr.encode();
        let code = code.as_ref();
        unsafe {
            _update_validity_predicate(
                addr.as_ptr() as _,
                addr.len() as _,
                code.as_ptr() as _,
                code.len() as _,
            )
        };
    }

    // Initialize a new account
    pub fn init_account(code: impl AsRef<[u8]>) -> Address {
        let code = code.as_ref();
        let result = Vec::with_capacity(0);
        let result_len = unsafe {
            _init_account(
                code.as_ptr() as _,
                code.len() as _,
                result.as_ptr() as _,
            )
        };
        let slice =
            unsafe { slice::from_raw_parts(result.as_ptr(), result_len as _) };
        Address::try_from_slice(slice)
            .expect("Decoding address created by the ledger shouldn't fail")
    }

    /// Get the chain ID
    pub fn get_chain_id() -> String {
        let result = Vec::with_capacity(CHAIN_ID_LENGTH);
        unsafe {
            _get_chain_id(result.as_ptr() as _);
        }
        let slice = unsafe {
            slice::from_raw_parts(result.as_ptr(), CHAIN_ID_LENGTH as _)
        };
        String::from_utf8(slice.to_vec()).expect("Cannot convert the ID string")
    }

    /// Get the committed block height
    pub fn get_block_height() -> BlockHeight {
        BlockHeight(unsafe { _get_block_height() })
    }

    /// Get a block hash
    pub fn get_block_hash() -> BlockHash {
        let result = Vec::with_capacity(BLOCK_HASH_LENGTH);
        unsafe {
            _get_block_hash(result.as_ptr() as _);
        }
        let slice = unsafe {
            slice::from_raw_parts(result.as_ptr(), BLOCK_HASH_LENGTH as _)
        };
        BlockHash::try_from(slice).expect("Cannot convert the hash")
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
        // Read variable-length data when we don't know the size up-front,
        // returns the size of the value (can be 0), or -1 if the key is
        // not present.
        fn _read(key_ptr: u64, key_len: u64, result_ptr: u64) -> i64;

        // Returns 1 if the key is present, 0 otherwise.
        fn _has_key(key_ptr: u64, key_len: u64) -> u64;

        // Write key/value, returns 1 on success, 0 otherwise.
        fn _write(key_ptr: u64, key_len: u64, val_ptr: u64, val_len: u64);

        // Delete the given key and its value, returns 1 on success, 0
        // otherwise.
        fn _delete(key_ptr: u64, key_len: u64) -> u64;

        // Get an ID of a data iterator with key prefix
        fn _iter_prefix(prefix_ptr: u64, prefix_len: u64) -> u64;

        // Read variable-length data when we don't know the size up-front,
        // returns the size of the value (can be 0), or -1 if the key is not
        // present.
        fn _iter_next(iter_id: u64, result_ptr: u64) -> i64;

        // Insert a verifier
        fn _insert_verifier(addr_ptr: u64, addr_len: u64);

        // Update a validity predicate
        fn _update_validity_predicate(
            addr_ptr: u64,
            addr_len: u64,
            code_ptr: u64,
            code_len: u64,
        );

        // Initialize a new account
        fn _init_account(code_ptr: u64, code_len: u64, result_ptr: u64) -> u64;

        // Get the chain ID
        fn _get_chain_id(result_ptr: u64);

        // Get the current block height
        fn _get_block_height() -> u64;

        // Get the current block hash
        fn _get_block_hash(result_ptr: u64);

        // Requires a node running with "Info" log level
        fn _log_string(str_ptr: u64, str_len: u64);
    }
}

/// Validity predicate environment imports
/// TODO: Add C interface for calling the host env
/// Transactions are not limited to smart contracts?
/// We don't have smart contracts
pub mod vp {
    pub use core::slice;
    use std::convert::TryFrom;
    use std::marker::PhantomData;
    pub use std::mem::size_of;

    use anoma_shared::types::key::ed25519::{PublicKey, Signature};
    use anoma_shared::types::{
        BlockHash, BlockHeight, BLOCK_HASH_LENGTH, CHAIN_ID_LENGTH,
    };
    use anoma_shared::vm_memory::KeyVal;
    pub use borsh::{BorshDeserialize, BorshSerialize};

    /// This macro expects a function with signature:
    ///
    /// ```ignore
    /// fn validate_tx(tx_data: vm_memory::Data, addr: Address, keys_changed: HashSet<Address>) -> bool
    /// ```
    #[macro_export]
    macro_rules! validity_predicate {
        (fn $fn:ident ( $($arg:ident : $type:ty),* $(,)?) -> $ret:ty $body:block ) => {
            use wee_alloc;

            // Use `wee_alloc` as the global allocator.
            #[global_allocator]
            static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

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
                let slice = unsafe {
                    slice::from_raw_parts(addr_ptr as *const u8, addr_len as _)
                };
                let addr = Address::try_from_slice(slice).unwrap();

                let slice = unsafe {
                    slice::from_raw_parts(
                        tx_data_ptr as *const u8,
                        tx_data_len as _,
                    )
                };
                let tx_data = slice.to_vec() as vm_memory::Data;

                let slice = unsafe {
                    slice::from_raw_parts(
                        keys_changed_ptr as *const u8,
                        keys_changed_len as _,
                    )
                };
                let keys_changed: Vec<Key> = Vec::try_from_slice(slice).unwrap();

                let slice = unsafe {
                    slice::from_raw_parts(
                        verifiers_ptr as *const u8,
                        verifiers_len as _,
                    )
                };
                let verifiers: HashSet<Address> = HashSet::try_from_slice(slice).unwrap();

                // run validation with the concrete type(s)
                if $fn(tx_data, addr, keys_changed, verifiers) {
                    1
                } else {
                    0
                }
            }
        }
    }
    pub struct PreKeyValIterator<T>(pub u64, pub PhantomData<T>);
    pub struct PostKeyValIterator<T>(pub u64, pub PhantomData<T>);

    /// Try to read a variable-length value at the given key from storage before
    /// transaction execution.
    pub fn read_pre<K: AsRef<str>, T: BorshDeserialize>(key: K) -> Option<T> {
        let key = key.as_ref();
        let size = size_of::<T>();
        let result = Vec::with_capacity(size);
        let size = unsafe {
            _read_pre(key.as_ptr() as _, key.len() as _, result.as_ptr() as _)
        };
        if size == -1 {
            None
        } else {
            let slice =
                unsafe { slice::from_raw_parts(result.as_ptr(), size as _) };
            T::try_from_slice(slice).ok()
        }
    }

    /// Try to read a variable-length value at the given key from storage after
    /// transaction execution.
    pub fn read_post<K: AsRef<str>, T: BorshDeserialize>(key: K) -> Option<T> {
        let key = key.as_ref();
        let size = size_of::<T>();
        let result = Vec::with_capacity(size);
        let size = unsafe {
            _read_post(key.as_ptr() as _, key.len() as _, result.as_ptr() as _)
        };
        if size == -1 {
            None
        } else {
            let slice =
                unsafe { slice::from_raw_parts(result.as_ptr(), size as _) };
            T::try_from_slice(slice).ok()
        }
    }

    /// Check if the given key was present in storage before transaction
    /// execution.
    pub fn has_key_pre(key: impl AsRef<str>) -> bool {
        let key = key.as_ref();
        let found = unsafe { _has_key_pre(key.as_ptr() as _, key.len() as _) };
        found == 1
    }

    /// Check if the given key is present in storage after transaction
    /// execution.
    pub fn has_key_post(key: impl AsRef<str>) -> bool {
        let key = key.as_ref();
        let found = unsafe { _has_key_post(key.as_ptr() as _, key.len() as _) };
        found == 1
    }

    /// Get an iterator with the given prefix before transaction execution
    pub fn iter_prefix_pre<K: AsRef<str>, T: BorshDeserialize>(
        prefix: K,
    ) -> PreKeyValIterator<T> {
        let prefix = prefix.as_ref();
        let iter_id =
            unsafe { _iter_prefix(prefix.as_ptr() as _, prefix.len() as _) };
        PreKeyValIterator(iter_id, PhantomData)
    }

    impl<T: BorshDeserialize> Iterator for PreKeyValIterator<T> {
        type Item = (String, T);

        fn next(&mut self) -> Option<(String, T)> {
            let result: Vec<u8> = Vec::with_capacity(0);
            let size = unsafe { _iter_pre_next(self.0, result.as_ptr() as _) };
            if size == -1 {
                None
            } else {
                let slice = unsafe {
                    slice::from_raw_parts(result.as_ptr(), size as _)
                };
                match KeyVal::try_from_slice(slice) {
                    Ok(key_val) => match T::try_from_slice(&key_val.val) {
                        Ok(v) => Some((key_val.key, v)),
                        Err(_) => None,
                    },
                    Err(_) => None,
                }
            }
        }
    }

    /// Get an iterator with the given prefix after transaction execution
    pub fn iter_prefix_post<K: AsRef<str>, T: BorshDeserialize>(
        prefix: K,
    ) -> PostKeyValIterator<T> {
        let prefix = prefix.as_ref();
        let iter_id =
            unsafe { _iter_prefix(prefix.as_ptr() as _, prefix.len() as _) };
        PostKeyValIterator(iter_id, PhantomData)
    }

    impl<T: BorshDeserialize> Iterator for PostKeyValIterator<T> {
        type Item = (String, T);

        fn next(&mut self) -> Option<(String, T)> {
            let result: Vec<u8> = Vec::with_capacity(0);
            let size = unsafe { _iter_post_next(self.0, result.as_ptr() as _) };
            if size == -1 {
                None
            } else {
                let slice = unsafe {
                    slice::from_raw_parts(result.as_ptr(), size as _)
                };
                match KeyVal::try_from_slice(slice) {
                    Ok(key_val) => match T::try_from_slice(&key_val.val) {
                        Ok(v) => Some((key_val.key, v)),
                        Err(_) => None,
                    },
                    Err(_) => None,
                }
            }
        }
    }

    /// Get the chain ID
    pub fn get_chain_id() -> String {
        let result = Vec::with_capacity(CHAIN_ID_LENGTH);
        unsafe {
            _get_chain_id(result.as_ptr() as _);
        }
        let slice = unsafe {
            slice::from_raw_parts(result.as_ptr(), CHAIN_ID_LENGTH as _)
        };
        String::from_utf8(slice.to_vec()).expect("Cannot convert the ID string")
    }

    /// Get the committed block height
    pub fn get_block_height() -> BlockHeight {
        BlockHeight(unsafe { _get_block_height() })
    }

    /// Get a block hash
    pub fn get_block_hash() -> BlockHash {
        let result = Vec::with_capacity(BLOCK_HASH_LENGTH);
        unsafe {
            _get_block_hash(result.as_ptr() as _);
        }
        let slice = unsafe {
            slice::from_raw_parts(result.as_ptr(), BLOCK_HASH_LENGTH as _)
        };
        BlockHash::try_from(slice).expect("Cannot convert the hash")
    }

    /// Verify a transaction signature. The signature is expected to have been
    /// produced on the data concatenated with the transaction code.
    pub fn verify_tx_signature(
        pk: &PublicKey,
        data: &[u8],
        sig: &Signature,
    ) -> bool {
        let pk = BorshSerialize::try_to_vec(pk).unwrap();
        let sig = BorshSerialize::try_to_vec(sig).unwrap();
        let valid = unsafe {
            _verify_tx_signature(
                pk.as_ptr() as _,
                pk.len() as _,
                data.as_ptr() as _,
                data.len() as _,
                sig.as_ptr() as _,
                sig.len() as _,
            )
        };
        valid == 1
    }

    /// Log a string. The message will be printed at the [`log::Level::Info`].
    pub fn log_string<T: AsRef<str>>(msg: T) {
        let msg = msg.as_ref();
        unsafe {
            _log_string(msg.as_ptr() as _, msg.len() as _);
        }
    }

    pub fn eval(vp_code: Vec<u8>, input_data: Vec<u8>) -> bool {
        let result = unsafe {
            _eval(
                vp_code.as_ptr() as _,
                vp_code.len() as _,
                input_data.as_ptr() as _,
                input_data.len() as _,
            )
        };
        result == 1
    }

    /// These host functions are implemented in the Anoma's [`host_env`]
    /// module. The environment provides calls to them via this C interface.
    extern "C" {
        // Read variable-length prior state when we don't know the size
        // up-front, returns the size of the value (can be 0), or -1 if
        // the key is not present.
        fn _read_pre(key_ptr: u64, key_len: u64, result_ptr: u64) -> i64;

        // Read variable-length posterior state when we don't know the size
        // up-front, returns the size of the value (can be 0), or -1 if
        // the key is not present.
        fn _read_post(key_ptr: u64, key_len: u64, result_ptr: u64) -> i64;

        // Returns 1 if the key is present in prior state, 0 otherwise.
        fn _has_key_pre(key_ptr: u64, key_len: u64) -> u64;

        // Returns 1 if the key is present in posterior state, 0 otherwise.
        fn _has_key_post(key_ptr: u64, key_len: u64) -> u64;

        // Get an ID of a data iterator with key prefix
        fn _iter_prefix(prefix_ptr: u64, prefix_len: u64) -> u64;

        // Read variable-length prior state when we don't know the size
        // up-front, returns the size of the value (can be 0), or -1 if
        // the key is not present.
        fn _iter_pre_next(iter_id: u64, result_ptr: u64) -> i64;

        // Read variable-length posterior state when we don't know the size
        // up-front, returns the size of the value (can be 0), or -1 if the
        // key is not present.
        fn _iter_post_next(iter_id: u64, result_ptr: u64) -> i64;

        // Get the chain ID
        fn _get_chain_id(result_ptr: u64);

        // Get the current block height
        fn _get_block_height() -> u64;

        // Get the current block hash
        fn _get_block_hash(result_ptr: u64);

        // Verify a transaction signature
        fn _verify_tx_signature(
            pk_ptr: u64,
            pk_len: u64,
            data_ptr: u64,
            data_len: u64,
            sig_ptr: u64,
            sig_len: u64,
        ) -> u64;

        // Requires a node running with "Info" log level
        fn _log_string(str_ptr: u64, str_len: u64);

        fn _eval(
            vp_code_ptr: u64,
            vp_code_len: u64,
            input_data_ptr: u64,
            input_data_len: u64,
        ) -> u64; // wasm doesn't have bool, so we return u64 
    }
}

/// Matchmaker environment imports
pub mod matchmaker {
    pub use core::slice;

    pub use borsh::{BorshDeserialize, BorshSerialize};

    /// This macro expects a function with signature:
    ///
    /// ```ignore
    /// fn match_intent(intent_1: Intent, intent_2: Intent) -> bool
    /// ```
    #[macro_export]
    macro_rules! matchmaker {
        (fn $fn:ident ( $($arg:ident : $type:ty),* $(,)?) -> $ret:ty $body:block ) => {
            use wee_alloc;

            // Use `wee_alloc` as the global allocator.
            #[global_allocator]
            static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

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
        // Inject a transaction from matchmaker's matched intents to the ledger
        pub fn _send_match(data_ptr: u64, data_len: u64);

        // Requires a node running with "Info" log level
        pub fn _log_string(str_ptr: u64, str_len: u64);
    }
}

/// Filter environment imports
pub mod filter {
    pub use core::slice;

    pub use borsh::{BorshDeserialize, BorshSerialize};

    /// This macro expects a function with signature:
    ///
    /// ```ignore
    /// fn validate_intent(intent: Vec<u8>) -> bool
    /// ```
    #[macro_export]
    macro_rules! filter {
        (fn $fn:ident ( $($arg:ident : $type:ty),* $(,)?) -> $ret:ty $body:block ) => {
            use wee_alloc;

            // Use `wee_alloc` as the global allocator.
            #[global_allocator]
            static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

            fn $fn( $($arg: $type),* ) -> $ret $body

            /// The module interface callable by wasm runtime
            #[no_mangle]
            extern "C" fn _validate_intent(
                intent_data_ptr: u64,
                intent_data_len: u64,
            ) -> u64 {
                let get_intent_data = |ptr, len| {
                    let slice = unsafe {
                        slice::from_raw_parts(ptr as *const u8, len as _)
                    };
                    slice.to_vec()
                };

                if $fn(
                    get_intent_data(intent_data_ptr, intent_data_len),
                ) {
                    0
                } else {
                    1
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
        // Requires a node running with "Info" log level
        pub fn _log_string(str_ptr: u64, str_len: u64);
    }
}
