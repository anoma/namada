//! A VP for a fungible token. Enforces that the total supply is unchanged in a
//! transaction that moves balance(s).

use anoma_vp_prelude::*;

#[validity_predicate]
fn validate_tx(
    _tx_data: Vec<u8>,
    addr: Address,
    keys_changed: BTreeSet<storage::Key>,
    verifiers: BTreeSet<Address>,
) -> bool {
    debug_log!(
        "validate_tx called with token addr: {}, key_changed: {:?}, \
         verifiers: {:?}",
        addr,
        keys_changed,
        verifiers
    );

    token::vp(&addr, &keys_changed, &verifiers)
}
