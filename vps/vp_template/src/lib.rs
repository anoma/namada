#[allow(unused_imports)]
use anoma_data_template::*;
use anoma_vm_env::{validity_predicate, vp_prelude::*};
use std::collections::HashSet;

validity_predicate! {
    fn validate_tx(tx_data: vm_memory::Data, addr: Address, keys_changed: Vec<Key>, verifiers: HashSet<Address>) -> bool {
        log_string(format!(
            "validate_tx called with addr: {}, key_changed: {:#?}, tx_data: {:#?}, verifiers: {:?}",
            addr, keys_changed, tx_data, verifiers
        ));

        for key in keys_changed.iter() {
            let key = key.to_string();
            let pre: Option<u64> = read_pre_varlen(&key);
            let post: Option<u64> = read_post_varlen(&key);
            log_string(format!(
                "validate_tx key: {}, pre: {:#?}, post: {:#?}",
                key, pre, post,
            ));
        }
        true
    }
}
