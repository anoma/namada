use std::collections::HashSet;

use anoma_shared::token::{balance_key, Amount, Change};
use anoma_shared::types::{Address, Key};

pub fn validity_predicate<FB, FA>(
    token: &Address,
    keys_changed: &[Key],
    verifiers: &HashSet<Address>,
    read_balance_pre: FB,
    read_balance_post: FA,
) -> bool
where
    FB: Fn(&str) -> Option<Amount>,
    FA: Fn(&str) -> Option<Amount>,
{
    let mut change: Change = 0;
    let all_checked = keys_changed.iter().all(|key| {
        key.find_addresses()
            .iter()
            .filter(|addr| *addr != token)
            .all(|addr| {
                let key = balance_key(token, addr).to_string();
                let pre = read_balance_pre(&key).unwrap_or_default();
                let post = read_balance_post(&key).unwrap_or_default();
                change += post.change();
                change -= pre.change();
                verifiers.contains(addr)
            })
    });
    all_checked && change == 0
}

pub fn transfer<F, FR, FW>(
    src: &Address,
    dest: &Address,
    token: &Address,
    amount: Amount,
    log_string: F,
    read: FR,
    write: FW,
) where
    F: Fn(String),
    FR: Fn(&str) -> Option<Amount>,
    FW: Fn(&str, Amount),
{
    let src_key = balance_key(token, src);
    let dest_key = balance_key(token, dest);
    let src_bal = read(&src_key.to_string());
    match src_bal {
        None => {
            log_string(format!("src {} has no balance", src));
            unreachable!()
        }
        Some(mut src_bal) => {
            src_bal.spend(&amount);
            let mut dest_bal = read(&dest_key.to_string()).unwrap_or_default();
            dest_bal.receive(&amount);
            write(&src_key.to_string(), src_bal);
            write(&dest_key.to_string(), dest_bal);
        }
    }
}
