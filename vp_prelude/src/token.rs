//! A fungible token validity predicate.

use std::collections::BTreeSet;

use namada_core::types::address::{self, Address, InternalAddress};
use namada_core::types::storage::Key;
/// Vp imports and functions.
use namada_core::types::storage::KeySeg;
use namada_core::types::token;
pub use namada_core::types::token::*;

use super::*;

/// A token validity predicate.
pub fn vp(
    ctx: &Ctx,
    token: &Address,
    keys_changed: &BTreeSet<Key>,
    verifiers: &BTreeSet<Address>,
) -> VpResult {
    let mut change: Change = 0;
    for key in keys_changed.iter() {
        let owner: Option<&Address> =
            match token::is_multitoken_balance_key(token, key) {
                Some((_, o)) => Some(o),
                None => token::is_balance_key(token, key),
            };
        match owner {
            None => {
                // Unknown changes to this address space are disallowed, but
                // unknown changes anywhere else are permitted
                if key.segments.get(0) == Some(&token.to_db_key()) {
                    return reject();
                }
            }
            Some(owner) => {
                // accumulate the change
                let pre: Amount = match owner {
                    Address::Internal(InternalAddress::IbcMint) => {
                        Amount::max()
                    }
                    Address::Internal(InternalAddress::IbcBurn) => {
                        Amount::default()
                    }
                    _ => ctx.read_pre(key)?.unwrap_or_default(),
                };
                let post: Amount = match owner {
                    Address::Internal(InternalAddress::IbcMint) => {
                        ctx.read_temp(key)?.unwrap_or_else(Amount::max)
                    }
                    Address::Internal(InternalAddress::IbcBurn) => {
                        ctx.read_temp(key)?.unwrap_or_default()
                    }
                    _ => ctx.read_post(key)?.unwrap_or_default(),
                };
                let this_change = post.change() - pre.change();
                change += this_change;
                // make sure that the spender approved the transaction
                if this_change < 0
                    && !(verifiers.contains(owner) || *owner == address::masp())
                {
                    return reject();
                }
            }
        }
    }
    Ok(change == 0)
}
