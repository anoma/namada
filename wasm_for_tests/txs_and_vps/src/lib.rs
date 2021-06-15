#[cfg(feature = "tx_no_op")]
pub mod tx_no_op {
    use anoma_vm_env::tx_prelude::*;

    #[transaction]
    fn apply_tx(_tx_data: Vec<u8>) {}
}

#[cfg(feature = "vp_always_true")]
pub mod vp_always_true {
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
pub mod vp_always_false {
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
