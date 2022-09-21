//! A VP for a fungible token. Enforces that the total supply is unchanged in a
//! transaction that moves balance(s).

use namada_vp_prelude::*;

#[validity_predicate]
fn validate_tx(
    tx_data: Vec<u8>,
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

    if !is_valid_tx(&tx_data) {
        return false;
    }

    let vp_check =
        keys_changed
            .iter()
            .all(|key| match key.is_validity_predicate() {
                Some(_) => {
                    let vp: Vec<u8> = read_bytes_post(key.to_string()).unwrap();
                    is_vp_whitelisted(&vp)
                }
                None => true,
            });

    vp_check && token::vp(&addr, &keys_changed, &verifiers)
}
