#[cfg(feature = "tx_no_op")]
pub mod main {
    use anoma_vm_env::tx_prelude::*;

    #[transaction]
    fn apply_tx(_tx_data: Vec<u8>) {}
}

#[cfg(feature = "tx_memory_limit")]
pub mod main {
    use anoma_vm_env::tx_prelude::*;

    #[transaction]
    fn apply_tx(tx_data: Vec<u8>) {
        // Allocates a memory of size given from the `tx_data (usize)`
        let len = usize::try_from_slice(&tx_data[..]).unwrap();
        log_string(format!("allocate len {}", len));
        let bytes: Vec<u8> = vec![6_u8; len];
        // use the variable to prevent it from compiler optimizing it away
        log_string(format!("{:?}", &bytes[..8]));
    }
}

#[cfg(feature = "vp_always_true")]
pub mod main {
    use std::collections::HashSet;

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

#[cfg(feature = "vp_always_false")]
pub mod main {
    use std::collections::HashSet;

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

#[cfg(feature = "vp_memory_limit")]
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
        let len = usize::try_from_slice(&tx_data[..]).unwrap();
        log_string(format!("allocate len {}", len));
        let bytes: Vec<u8> = vec![6_u8; len];
        // use the variable to prevent it from compiler optimizing it away
        log_string(format!("{:?}", &bytes[..8]));
        true
    }
}
