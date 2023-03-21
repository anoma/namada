//! A VP for a fungible token. Enforces that the total supply is unchanged in a
//! transaction that moves balance(s).

use std::collections::BTreeSet;

use namada_vp_prelude::address::{self, Address, InternalAddress};
use namada_vp_prelude::storage::KeySeg;
use namada_vp_prelude::{storage, token, *};

#[validity_predicate]
fn validate_tx(
    ctx: &Ctx,
    tx_data: Vec<u8>,
    addr: Address,
    keys_changed: BTreeSet<storage::Key>,
    verifiers: BTreeSet<Address>,
) -> VpResult {
    debug_log!(
        "validate_tx called with token addr: {}, key_changed: {:?}, \
         verifiers: {:?}",
        addr,
        keys_changed,
        verifiers
    );

    if !is_valid_tx(ctx, &tx_data)? {
        return reject();
    }

    for key in keys_changed.iter() {
        if key.is_validity_predicate().is_some() {
            let vp: Vec<u8> = ctx.read_bytes_post(key)?.unwrap();
            if !is_vp_whitelisted(ctx, &vp)? {
                return reject();
            }
        }
    }

    token_checks(ctx, &addr, &keys_changed, &verifiers)
}

/// A token validity predicate checks that the total supply is preserved.
/// This implies that:
///
/// - The value associated with the `total_supply` storage key may not change.
/// - For any balance changes, the total of outputs must be equal to the total
///   of inputs.
fn token_checks(
    ctx: &Ctx,
    token: &Address,
    keys_touched: &BTreeSet<storage::Key>,
    verifiers: &BTreeSet<Address>,
) -> VpResult {
    let mut change: token::Change = 0;
    for key in keys_touched.iter() {
        let owner: Option<&Address> = token::is_balance_key(token, key)
            .or_else(|| {
                token::is_multitoken_balance_key(token, key).map(|a| a.1)
            });

        match owner {
            None => {
                if token::is_total_supply_key(key, token) {
                    // check if total supply is changed, which it should never
                    // be from a tx
                    let total_pre: token::Amount = ctx.read_pre(key)?.unwrap();
                    let total_post: token::Amount =
                        ctx.read_post(key)?.unwrap();
                    if total_pre != total_post {
                        return reject();
                    }
                } else if key.segments.get(0) == Some(&token.to_db_key()) {
                    // Unknown changes to this address space are disallowed, but
                    // unknown changes anywhere else are permitted
                    return reject();
                }
            }
            Some(owner) => {
                // accumulate the change
                let pre: token::Amount = match owner {
                    Address::Internal(InternalAddress::IbcMint) => {
                        token::Amount::max()
                    }
                    Address::Internal(InternalAddress::IbcBurn) => {
                        token::Amount::default()
                    }
                    _ => ctx.read_pre(key)?.unwrap_or_default(),
                };
                let post: token::Amount = match owner {
                    Address::Internal(InternalAddress::IbcMint) => {
                        ctx.read_temp(key)?.unwrap_or_else(token::Amount::max)
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
}
