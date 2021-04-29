use std::collections::HashSet;

use anoma_vm_env::validity_predicate;
use anoma_vm_env::vp_prelude::*;

validity_predicate! {
    fn validate_tx(tx_data: vm_memory::Data, addr: Address, keys_changed: Vec<Key>, verifiers: HashSet<Address>) -> bool {
        log_string(format!(
            "validate_tx called with user addr: {}, key_changed: {:#?}, tx_data: {:#?}, verifiers: {:?}",
            addr, keys_changed, tx_data, verifiers
        ));

        let valid_sig = match key::ed25519::SignedTxData::try_from_slice(&tx_data[..]) {
            Ok(tx) => {
                let pk = key::ed25519::get(&addr);
                match pk {
                    None => false,
                    Some(pk) => {
                        verify_tx_signature(&pk, &tx.data, &tx.sig)
                    }
                }
            },
            _ => false,
        };

        for key in keys_changed.iter() {
            match token::is_any_token_balance_key(key) {
                Some(owner) if owner == &addr => {
                    let key = key.to_string();
                    let pre: token::Amount = read_pre(&key).unwrap_or_default();
                    let post: token::Amount = read_post(&key).unwrap_or_default();
                    let change = post.change() - pre.change();
                    log_string(format!(
                        "token key: {}, change: {}, valid_sig: {}",
                        key, change, valid_sig,
                    ));
                    // debit has to signed, credit doesn't
                    if change < 0 && !valid_sig {
                        return false;
                    }
                },
                _ => {
                    // decline any other changes unless the signature is valid
                    if !valid_sig {
                        return false;
                    }
                }
            }
        }
        true
    }
}
