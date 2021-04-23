#[allow(unused_imports)]
use anoma_data_template::*;
use anoma_vm_env::{validity_predicate, vp_prelude::*};
use std::collections::HashSet;

validity_predicate! {
    fn validate_tx(tx_data: vm_memory::Data, addr: Address, keys_changed: Vec<Key>, verifiers: HashSet<Address>) -> bool {
        log_string(format!(
            "validate_tx called with token addr: {}, key_changed: {:#?}, tx_data: {:#?}, verifiers: {:?}",
            addr, keys_changed, tx_data, verifiers
        ));

        token::validity_predicate(&addr, &keys_changed, &verifiers, |key| read_pre(key), |key| read_post(key))
    }
}
