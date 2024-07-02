//! Shielded and transparent tokens related functions

use std::collections::BTreeMap;

use namada_core::address::Address;
use namada_events::{EmitEvents, EventLevel};
#[cfg(any(test, feature = "testing"))]
pub use namada_token::testing;
pub use namada_token::{
    storage_key, utils, Amount, DenominatedAmount, Transfer,
};
use namada_tx_env::TxEnv;

use crate::{Ctx, TxResult};

/// A transparent token transfer that can be used in a transaction.
pub fn transfer(
    ctx: &mut Ctx,
    src: &Address,
    dest: &Address,
    token: &Address,
    amount: Amount,
) -> TxResult {
    use namada_token::event::{TokenEvent, TokenOperation, UserAccount};

    // The tx must be authorized by the source address
    ctx.insert_verifier(src)?;
    if token.is_internal() {
        // Established address tokens do not have VPs themselves, their
        // validation is handled by the `Multitoken` internal address, but
        // internal token addresses have to verify the transfer
        ctx.insert_verifier(token)?;
    }

    namada_token::transfer(ctx, token, src, dest, amount)?;

    ctx.emit(TokenEvent {
        descriptor: "transfer-from-wasm".into(),
        level: EventLevel::Tx,
        token: token.clone(),
        operation: TokenOperation::Transfer {
            amount: amount.into(),
            source: UserAccount::Internal(src.clone()),
            target: UserAccount::Internal(dest.clone()),
            source_post_balance: namada_token::read_balance(ctx, token, src)?
                .into(),
            target_post_balance: Some(
                namada_token::read_balance(ctx, token, dest)?.into(),
            ),
        },
    });

    Ok(())
}

/// A transparent token transfer that can be used in a transaction.
pub fn multi_transfer(
    ctx: &mut Ctx,
    sources: &BTreeMap<(Address, Address), Amount>,
    dests: &BTreeMap<(Address, Address), Amount>,
) -> TxResult {
    for (src, token) in sources.keys() {
        // The tx must be authorized by the source address
        ctx.insert_verifier(src)?;
        if token.is_internal() {
            // Established address tokens do not have VPs themselves, their
            // validation is handled by the `Multitoken` internal address, but
            // internal token addresses have to verify the transfer
            ctx.insert_verifier(token)?;
        }
    }

    for (_, token) in dests.keys() {
        if token.is_internal() {
            // Established address tokens do not have VPs themselves, their
            // validation is handled by the `Multitoken` internal address, but
            // internal token addresses have to verify the transfer
            ctx.insert_verifier(token)?;
        }
    }

    namada_token::multi_transfer(ctx, sources, dests)?;

    Ok(())
}
