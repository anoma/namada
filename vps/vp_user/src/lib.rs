use std::collections::HashSet;

use anoma_vm_env::validity_predicate;
use anoma_vm_env::vp_prelude::intent::{Intent, IntentTransfers};
use anoma_vm_env::vp_prelude::key::ed25519::{Signed, SignedTxData};
use anoma_vm_env::vp_prelude::*;

const VP: &[u8] = include_bytes!("../../vp_template/vp.wasm");

validity_predicate! {
    fn validate_tx(tx_data: vm_memory::Data, addr: Address, keys_changed: Vec<Key>, verifiers: HashSet<Address>) -> bool {
        log_string(format!(
            "validate_tx called with user addr: {}, key_changed: {:#?}, verifiers: {:?}",
            addr, keys_changed, verifiers
        ));

        let result = eval(VP.to_vec(), vec![1_u8, 0_u8]);
        log_string(format!("eval result {}", result));


        true

        // // TODO memoize?
        // let valid_sig = match SignedTxData::try_from_slice(&tx_data[..]) {
        //     Ok(tx) => {
        //         let pk = key::ed25519::get(&addr);
        //         match pk {
        //             None => false,
        //             Some(pk) => {
        //                 verify_tx_signature(&pk, &tx.data, &tx.sig)
        //             }
        //         }
        //     },
        //     _ => false,
        // };

        // // TODO memoize?
        // // TODO this is not needed for matchmaker, maybe we should have a different VP?
        // let valid_intent = check_intent_transfers(&addr, &tx_data[..]);

        // for key in keys_changed.iter() {
        //     match token::is_any_token_balance_key(key) {
        //         Some(owner) if owner == &addr => {
        //             let key = key.to_string();
        //             let pre: token::Amount = read_pre(&key).unwrap_or_default();
        //             let post: token::Amount = read_post(&key).unwrap_or_default();
        //             let change = post.change() - pre.change();
        //             log_string(format!(
        //                 "token key: {}, change: {}, valid_sig: {}, valid_intent: {}",
        //                 key, change, valid_sig, valid_intent,
        //             ));
        //             // debit has to signed, credit doesn't
        //             if change < 0 && !valid_sig && !valid_intent {
        //                 return false;
        //             }
        //         },
        //         _ => {
        //             // decline any other changes unless the signature is valid
        //             if !valid_sig {
        //                 return false;
        //             }
        //         }
        //     }
        // }
        // true
    }
}

fn check_intent_transfers(addr: &Address, tx_data: &[u8]) -> bool {
    match SignedTxData::try_from_slice(&tx_data[..]) {
        Ok(tx) => match IntentTransfers::try_from_slice(&tx.data[..]) {
            Err(_) => false,
            Ok(transfers) => {
                if &transfers.intent_1.data.addr == addr {
                    log_string(format!("check intent 1"));
                    check_intent(addr, &transfers.intent_1)
                } else if &transfers.intent_2.data.addr == addr {
                    log_string(format!("check intent 2"));
                    check_intent(addr, &transfers.intent_2)
                } else {
                    log_string(format!("no intent with a matching address"));
                    false
                }
            }
        },
        _ => false,
    }
}

fn check_intent(addr: &Address, intent: &Signed<Intent>) -> bool {
    // verify signature
    let pk = key::ed25519::get(addr);
    match pk {
        None => {
            return false;
        }
        Some(pk) => {
            if !intent.verify(&pk).is_ok() {
                log_string(format!("invalid sig"));
                return false;
            }
        }
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
    let sell_pre: token::Amount = read_pre(&token_sell_key).unwrap_or_default();
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
    let buy_pre: token::Amount = read_pre(&token_buy_key).unwrap_or_default();
    let buy_post: token::Amount = read_post(token_buy_key).unwrap_or_default();
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
