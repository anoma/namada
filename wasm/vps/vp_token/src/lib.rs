use std::collections::HashSet;

use anoma_vm_env::vp_prelude::*;

#[validity_predicate]
fn validate_tx(
    tx_data: Vec<u8>,
    addr: Address,
    keys_changed: Vec<storage::Key>,
    verifiers: HashSet<Address>,
) -> bool {
    log_string(format!(
        "validate_tx called with token addr: {}, key_changed: {:#?}, tx_data: \
         {:#?}, verifiers: {:?}",
        addr, keys_changed, tx_data, verifiers
    ));

    token::vp(&addr, &keys_changed, &verifiers)
}
