/// A tx for a token transfer crafted by matchmaker from intents.
/// This tx uses `intent::IntentTransfers` wrapped inside
/// `key::ed25519::SignedTxData` as its input as declared in `shared` crate.
#[cfg(feature = "tx_from_intent")]
pub mod tx_from_intent {
    use anoma_vm_env::tx_prelude::*;

    #[transaction]
    fn apply_tx(tx_data: Vec<u8>) {
        let signed =
            key::ed25519::SignedTxData::try_from_slice(&tx_data[..]).unwrap();
        let tx_data =
            intent::IntentTransfers::try_from_slice(&signed.data.unwrap()[..])
                .unwrap();
        log_string(format!(
            "apply_tx called with intent transfers: {:#?}",
            tx_data
        ));

        // make sure that the matchmaker has to validate this tx
        insert_verifier(address::matchmaker());

        for token::Transfer {
            source,
            target,
            token,
            amount,
        } in tx_data.transfers
        {
            token::transfer(&source, &target, &token, amount);
        }

        tx_data
            .intents
            .values()
            .into_iter()
            .for_each(intent::invalidate_intent);
    }
}

/// A tx for token transfer.
/// This tx uses `token::Transfer` wrapped inside `key::ed25519::SignedTxData`
/// as its input as declared in `shared` crate.
#[cfg(feature = "tx_transfer")]
pub mod tx_transfer {
    use anoma_vm_env::tx_prelude::*;

    #[transaction]
    fn apply_tx(tx_data: Vec<u8>) {
        let signed =
            key::ed25519::SignedTxData::try_from_slice(&tx_data[..]).unwrap();
        let transfer =
            token::Transfer::try_from_slice(&signed.data.unwrap()[..]).unwrap();
        log_string(format!("apply_tx called with transfer: {:#?}", transfer));
        let token::Transfer {
            source,
            target,
            token,
            amount,
        } = transfer;
        token::transfer(&source, &target, &token, amount)
    }
}

/// A tx for updating an account's validity predicate.
/// This tx wraps the validity predicate inside `key::ed25519::SignedTxData` as
/// its input as declared in `shared` crate.
#[cfg(feature = "tx_update_vp")]
pub mod tx_update_vp {
    use anoma_vm_env::tx_prelude::*;

    #[transaction]
    fn apply_tx(tx_data: Vec<u8>) {
        let signed =
            key::ed25519::SignedTxData::try_from_slice(&tx_data[..]).unwrap();
        let update_vp =
            transaction::UpdateVp::try_from_slice(&signed.data.unwrap()[..])
                .unwrap();
        log_string(format!("update VP for: {:#?}", update_vp.addr));
        update_validity_predicate(update_vp.addr, update_vp.vp_code)
    }
}

/// A VP for a token.
#[cfg(feature = "vp_token")]
pub mod vp_token {
    use anoma_vm_env::vp_prelude::*;

    #[validity_predicate]
    fn validate_tx(
        tx_data: Vec<u8>,
        addr: Address,
        keys_changed: HashSet<storage::Key>,
        verifiers: HashSet<Address>,
    ) -> bool {
        log_string(format!(
            "validate_tx called with token addr: {}, key_changed: {:#?}, \
             tx_data: {:#?}, verifiers: {:?}",
            addr, keys_changed, tx_data, verifiers
        ));

        token::vp(&addr, &keys_changed, &verifiers)
    }
}

/// A basic user VP.
/// This VP currently provides a signature verification against a public key for
/// sending tokens (receiving tokens is permissive).
#[cfg(feature = "vp_user")]
pub mod vp_user {
    use anoma_vm_env::vp_prelude::intent::{Intent, IntentTransfers};
    use anoma_vm_env::vp_prelude::key::ed25519::{Signed, SignedTxData};
    use anoma_vm_env::vp_prelude::*;

    enum KeyType<'a> {
        Token(&'a Address),
        InvalidIntentSet(&'a Address),
        Unknown,
    }

    impl<'a> From<&'a storage::Key> for KeyType<'a> {
        fn from(key: &'a storage::Key) -> KeyType<'a> {
            if let Some(address) = token::is_any_token_balance_key(key) {
                Self::Token(address)
            } else if let Some(address) = intent::is_invalid_intent_key(key) {
                Self::InvalidIntentSet(address)
            } else {
                Self::Unknown
            }
        }
    }

    #[validity_predicate]
    fn validate_tx(
        tx_data: Vec<u8>,
        addr: Address,
        keys_changed: HashSet<storage::Key>,
        verifiers: HashSet<Address>,
    ) -> bool {
        log_string(format!(
            "validate_tx called with user addr: {}, key_changed: {:#?}, \
             verifiers: {:?}",
            addr, keys_changed, verifiers
        ));

        // TODO memoize?
        let valid_sig = match SignedTxData::try_from_slice(&tx_data[..]) {
            Ok(tx) => {
                let pk = key::ed25519::get(&addr);
                match pk {
                    None => false,
                    Some(pk) => verify_tx_signature(&pk, &tx.sig),
                }
            }
            _ => false,
        };

        // TODO memoize?
        // TODO this is not needed for matchmaker, maybe we should have a
        // different VP?
        let valid_intent = check_intent_transfers(&addr, &tx_data[..]);

        for key in keys_changed.iter() {
            let is_valid = match KeyType::from(key) {
                KeyType::Token(owner) if owner == &addr => {
                    let key = key.to_string();
                    let pre: token::Amount = read_pre(&key).unwrap_or_default();
                    let post: token::Amount =
                        read_post(&key).unwrap_or_default();
                    let change = post.change() - pre.change();
                    log_string(format!(
                        "token key: {}, change: {}, valid_sig: {}, \
                         valid_intent: {}, valid modification: {}",
                        key,
                        change,
                        valid_sig,
                        valid_intent,
                        (change < 0 && (valid_sig || valid_intent))
                            || change > 0
                    ));
                    // debit has to signed, credit doesn't
                    (change < 0 && (valid_sig || valid_intent)) || change > 0
                }
                KeyType::InvalidIntentSet(owner) if owner == &addr => {
                    let key = key.to_string();
                    let pre: Vec<Vec<u8>> = read_pre(&key).unwrap_or_default();
                    let post: Vec<Vec<u8>> =
                        read_post(&key).unwrap_or_default();
                    // only one sig is added, intent is already checked
                    log_string(format!(
                        "intent sig set key: {}, valid modification: {}",
                        key,
                        pre.len() + 1 != post.len()
                    ));
                    pre.len() + 1 == post.len()
                }
                KeyType::Token(_owner) | KeyType::InvalidIntentSet(_owner) => {
                    log_string(format!(
                        "key {} is not of owner, valid_sig {}",
                        key, valid_sig
                    ));
                    valid_sig
                }
                KeyType::Unknown => {
                    log_string(format!(
                        "Unknown key modified, valid sig {}",
                        valid_sig
                    ));
                    valid_sig
                }
            };
            if !is_valid {
                log_string(format!("key {} modification failed vp", key));
                return false;
            }
        }
        true
    }

    fn check_intent_transfers(addr: &Address, tx_data: &[u8]) -> bool {
        match SignedTxData::try_from_slice(tx_data) {
            Ok(tx) => {
                match IntentTransfers::try_from_slice(&tx.data.unwrap()[..]) {
                    Ok(tx_data) => {
                        if let Some(intent) = &tx_data.intents.get(addr) {
                            log_string("check intent".to_string());
                            check_intent(addr, intent)
                        } else {
                            log_string(
                                "no intent with a matching address".to_string(),
                            );
                            false
                        }
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }

    fn check_intent(addr: &Address, intent: &Signed<Intent>) -> bool {
        // verify signature
        let pk = key::ed25519::get(addr);
        if let Some(pk) = pk {
            if intent.verify(&pk).is_err() {
                log_string("invalid sig".to_string());
                return false;
            }
        } else {
            return false;
        }

        // verify the intent have not been already used
        if !intent::vp(intent) {
            return false;
        }

        // verify the intent is fulfilled
        let Intent {
            addr: _,
            token_sell,
            amount_sell,
            token_buy,
            amount_buy,
        } = &intent.data;

        let token_sell_key = token::balance_key(&token_sell, addr).to_string();
        let sell_pre: token::Amount =
            read_pre(&token_sell_key).unwrap_or_default();
        let sell_post: token::Amount =
            read_post(token_sell_key).unwrap_or_default();

        // check that the sold token has been debited
        if sell_pre.change() - sell_post.change() != amount_sell.change() {
            log_string(format!(
                "invalid sell, {}, {}, {}",
                sell_pre.change(),
                sell_post.change(),
                amount_sell.change()
            ));
            return false;
        }

        let token_buy_key = token::balance_key(&token_buy, addr).to_string();
        let buy_pre: token::Amount =
            read_pre(&token_buy_key).unwrap_or_default();
        let buy_post: token::Amount =
            read_post(token_buy_key).unwrap_or_default();
        // check that the bought token has been credited
        let res = buy_post.change() - buy_pre.change() == amount_buy.change();
        if !res {
            log_string(format!(
                "invalid buy, {}, {}, {}",
                buy_pre.change(),
                buy_post.change(),
                amount_buy.change()
            ));
        }
        res
        // TODO once an intent is fulfilled, it should be invalidated somehow to
        // prevent replay
    }

    #[cfg(test)]
    mod tests {
        use anoma_tests::vp::*;

        use super::*;

        /// Test that no-op transaction (i.e. no storage modifications) is
        /// deemed valid.
        #[test]
        fn test_no_op_transaction() {
            let mut env = TestVpEnv::default();
            init_vp_env(&mut env);

            let tx_data: Vec<u8> = vec![];
            let addr: Address = env.addr;
            let keys_changed: HashSet<storage::Key> = HashSet::default();
            let verifiers: HashSet<Address> = HashSet::default();

            let valid = validate_tx(tx_data, addr, keys_changed, verifiers);

            assert!(valid);
        }
    }
}
