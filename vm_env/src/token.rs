use std::collections::HashSet;

use anoma_shared::token::{balance_key, Amount, Change};
use anoma_shared::types::{Address, Key};

use super::imports::{tx, vp};

pub fn validity_predicate(
    token: &Address,
    keys_changed: &[Key],
    verifiers: &HashSet<Address>,
) -> bool {
    let mut change: Change = 0;
    let all_checked = keys_changed.iter().all(|key| {
        key.find_addresses()
            .iter()
            .filter(|addr| *addr != token)
            .all(|addr| {
                let key = balance_key(token, addr).to_string();
                let pre: Amount = vp::read_pre(&key).unwrap_or_default();
                let post: Amount = vp::read_post(&key).unwrap_or_default();
                change += post.change();
                change -= pre.change();
                verifiers.contains(addr)
            })
    });
    all_checked && change == 0
}

pub fn transfer(
    src: &Address,
    dest: &Address,
    token: &Address,
    amount: Amount,
) {
    let src_key = balance_key(token, src);
    let dest_key = balance_key(token, dest);
    let src_bal: Option<Amount> = tx::read(&src_key.to_string());
    match src_bal {
        None => {
            tx::log_string(format!("src {} has no balance", src));
            unreachable!()
        }
        Some(mut src_bal) => {
            src_bal.spend(&amount);
            let mut dest_bal: Amount =
                tx::read(&dest_key.to_string()).unwrap_or_default();
            dest_bal.receive(&amount);
            tx::write(&src_key.to_string(), src_bal);
            tx::write(&dest_key.to_string(), dest_bal);
        }
    }
}
