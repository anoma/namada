use std::collections::BTreeSet;

use namada::types::address::{Address, InternalAddress};
use namada::types::storage::Key;
use namada::types::token;

/// Vp imports and functions.
pub mod vp {
    use namada::types::storage::KeySeg;
    pub use namada::types::token::*;

    use super::*;
    use crate::imports::vp;

    /// A token validity predicate.
    pub fn vp(
        token: &Address,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> bool {
        let mut change: Change = 0;
        let all_checked = keys_changed.iter().all(|key| {
            let owner: Option<&Address> =
                token::is_multitoken_balance_key(token, key)
                    .or_else(|| token::is_balance_key(token, key));
            match owner {
                None => {
                    // Unknown changes to this address space are disallowed, but
                    // unknown changes anywhere else are permitted
                    key.segments.get(0) != Some(&token.to_db_key())
                }
                Some(owner) => {
                    // accumulate the change
                    let key = key.to_string();
                    let pre: Amount = match owner {
                        Address::Internal(InternalAddress::IbcMint) => {
                            Amount::max()
                        }
                        Address::Internal(InternalAddress::IbcBurn) => {
                            Amount::default()
                        }
                        _ => vp::read_pre(&key).unwrap_or_default(),
                    };
                    let post: Amount = match owner {
                        Address::Internal(InternalAddress::IbcMint) => {
                            vp::read_temp(&key).unwrap_or_else(Amount::max)
                        }
                        Address::Internal(InternalAddress::IbcBurn) => {
                            vp::read_temp(&key).unwrap_or_default()
                        }
                        _ => vp::read_post(&key).unwrap_or_default(),
                    };
                    let this_change = post.change() - pre.change();
                    change += this_change;
                    // make sure that the spender approved the transaction
                    if this_change < 0 {
                        return verifiers.contains(owner);
                    }
                    true
                }
            }
        });
        all_checked && change == 0
    }
}

/// Tx imports and functions.
pub mod tx {
    pub use namada::types::token::*;

    use super::*;
    use crate::imports::tx;

    /// A token transfer that can be used in a transaction.
    pub fn transfer(
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: Amount,
    ) {
        let src_key = token::balance_key(token, src);
        let dest_key = token::balance_key(token, dest);
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

    /// A token transfer with storage keys that can be used in a transaction.
    pub fn multitoken_transfer(src_key: &Key, dest_key: &Key, amount: Amount) {
        let src_owner = is_any_multitoken_balance_key(src_key);
        let src_bal: Option<Amount> = match src_owner {
            Some(Address::Internal(InternalAddress::IbcMint)) => {
                Some(Amount::max())
            }
            Some(Address::Internal(InternalAddress::IbcBurn)) => {
                tx::log_string("invalid transfer from the burn address");
                unreachable!()
            }
            Some(_) => tx::read(&src_key.to_string()),
            None => {
                // the key is not multitoken key
                match is_any_token_balance_key(src_key) {
                    Some(_) => tx::read(src_key.to_string()),
                    None => {
                        tx::log_string(format!(
                            "invalid balance key: {}",
                            src_key
                        ));
                        unreachable!()
                    }
                }
            }
        };
        let mut src_bal = src_bal.unwrap_or_else(|| {
            tx::log_string(format!("src {} has no balance", src_key));
            unreachable!()
        });
        src_bal.spend(&amount);
        let dest_owner = is_any_multitoken_balance_key(dest_key);
        let mut dest_bal: Amount = match dest_owner {
            Some(Address::Internal(InternalAddress::IbcMint)) => {
                tx::log_string("invalid transfer to the mint address");
                unreachable!()
            }
            Some(_) => tx::read(dest_key.to_string()).unwrap_or_default(),
            None => match is_any_token_balance_key(dest_key) {
                Some(_) => tx::read(dest_key.to_string()).unwrap_or_default(),
                None => {
                    tx::log_string(format!(
                        "invalid balance key: {}",
                        dest_key
                    ));
                    unreachable!()
                }
            },
        };
        dest_bal.receive(&amount);
        match src_owner {
            Some(Address::Internal(InternalAddress::IbcMint)) => {
                tx::write_temp(&src_key.to_string(), src_bal)
            }
            _ => tx::write(&src_key.to_string(), src_bal),
        }
        match dest_owner {
            Some(Address::Internal(InternalAddress::IbcBurn)) => {
                tx::write_temp(&dest_key.to_string(), dest_bal)
            }
            _ => tx::write(&dest_key.to_string(), dest_bal),
        }
    }
}
