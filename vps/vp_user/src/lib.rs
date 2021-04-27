#[allow(unused_imports)]
use anoma_data_template::*;
use anoma_vm_env::{validity_predicate, vp_prelude::*};
use std::collections::HashSet;

validity_predicate! {
    fn validate_tx(tx_data: vm_memory::Data, addr: Address, keys_changed: Vec<Key>, verifiers: HashSet<Address>) -> bool {
        log_string(format!(
            "validate_tx called with user addr: {}, key_changed: {:#?}, tx_data: {:#?}, verifiers: {:?}",
            addr, keys_changed, tx_data, verifiers
        ));

        for key in keys_changed.iter() {
            match token::is_any_token_balance_key(key) {
                Some(owner) if owner == &addr => {
                    let key = key.to_string();
                    let pre: token::Amount = read_pre(&key).unwrap_or_default();
                    let post: token::Amount = read_post(&key).unwrap_or_default();
                    let change = post.change() - pre.change();
                    if change < 0 {
                        // TODO check signature
                        return false;
                    }
                },
                _ => {continue}
            }
        }
        true
    }
}
