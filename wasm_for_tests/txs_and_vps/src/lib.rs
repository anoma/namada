/// A tx that doesn't do anything.
#[cfg(feature = "tx_no_op")]
pub mod main {
    use anoma_vm_env::tx_prelude::*;

    #[transaction]
    fn apply_tx(_tx_data: Vec<u8>) {}
}

/// A tx that allocates a memory of size given from the `tx_data: usize`.
#[cfg(feature = "tx_memory_limit")]
pub mod main {
    use anoma_vm_env::tx_prelude::*;

    #[transaction]
    fn apply_tx(tx_data: Vec<u8>) {
        let len = usize::try_from_slice(&tx_data[..]).unwrap();
        log_string(format!("allocate len {}", len));
        let bytes: Vec<u8> = vec![6_u8; len];
        // use the variable to prevent it from compiler optimizing it away
        log_string(format!("{:?}", &bytes[..8]));
    }
}

/// A tx that attempts to read the given key from storage.
#[cfg(feature = "tx_read_storage_key")]
pub mod main {
    use anoma_vm_env::tx_prelude::*;

    #[transaction]
    fn apply_tx(tx_data: Vec<u8>) {
        // Allocates a memory of size given from the `tx_data (usize)`
        let key = storage::Key::try_from_slice(&tx_data[..]).unwrap();
        log_string(format!("key {}", key));
        let _result: Vec<u8> = read(key.to_string()).unwrap();
    }
}

/// A VP that always returns `true`.
#[cfg(feature = "vp_always_true")]
pub mod main {
    use anoma_vm_env::vp_prelude::*;

    #[validity_predicate]
    fn validate_tx(
        _tx_data: Vec<u8>,
        _addr: Address,
        _keys_changed: Vec<storage::Key>,
        _verifiers: HashSet<Address>,
    ) -> bool {
        true
    }
}

/// A VP that always returns `false`.
#[cfg(feature = "vp_always_false")]
pub mod main {
    use anoma_vm_env::vp_prelude::*;

    #[validity_predicate]
    fn validate_tx(
        _tx_data: Vec<u8>,
        _addr: Address,
        _keys_changed: Vec<storage::Key>,
        _verifiers: HashSet<Address>,
    ) -> bool {
        false
    }
}

// A VP that allocates a memory of size given from the `tx_data: usize`.
#[cfg(feature = "vp_memory_limit")]
pub mod main {
    use anoma_vm_env::vp_prelude::*;

    #[validity_predicate]
    fn validate_tx(
        tx_data: Vec<u8>,
        _addr: Address,
        _keys_changed: Vec<storage::Key>,
        _verifiers: HashSet<Address>,
    ) -> bool {
        let len = usize::try_from_slice(&tx_data[..]).unwrap();
        log_string(format!("allocate len {}", len));
        let bytes: Vec<u8> = vec![6_u8; len];
        // use the variable to prevent it from compiler optimizing it away
        log_string(format!("{:?}", &bytes[..8]));
        true
    }
}

/// A VP that attempts to read the given key from storage (state prior to tx
/// execution).
#[cfg(feature = "vp_read_storage_key")]
pub mod main {
    use std::collections::HashSet;

    use anoma_vm_env::vp_prelude::*;

    #[validity_predicate]
    fn validate_tx(
        tx_data: Vec<u8>,
        _addr: Address,
        _keys_changed: Vec<storage::Key>,
        _verifiers: HashSet<Address>,
    ) -> bool {
        // Allocates a memory of size given from the `tx_data (usize)`
        let key = storage::Key::try_from_slice(&tx_data[..]).unwrap();
        log_string(format!("key {}", key));
        let _result: Vec<u8> = read_pre(key.to_string()).unwrap();
        true
    }
}
