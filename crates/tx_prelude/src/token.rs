//! Shielded and transparent tokens related functions

use std::collections::BTreeMap;

use namada_core::address::Address;
use namada_core::collections::HashSet;
use namada_events::extend::UserAccount;
use namada_events::{EmitEvents, EventLevel};
use namada_token::event::{TokenEvent, TokenOperation};
#[cfg(any(test, feature = "testing"))]
pub use namada_token::testing;
pub use namada_token::{
    storage_key, utils, Amount, DenominatedAmount, Store, Transfer,
};
use namada_tx_env::ctx::{Ctx, TxResult};
use namada_tx_env::{Result, TxEnv};

/// A transparent token transfer that can be used in a transaction.
pub fn transfer(
    ctx: &mut Ctx,
    src: &Address,
    dest: &Address,
    token: &Address,
    amount: Amount,
) -> TxResult {
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
        operation: TokenOperation::transfer(
            UserAccount::Internal(src.clone()),
            UserAccount::Internal(dest.clone()),
            token.clone(),
            amount.into(),
            namada_token::read_balance(ctx, token, src)?.into(),
            Some(namada_token::read_balance(ctx, token, dest)?.into()),
        ),
    });

    Ok(())
}

/// A transparent token transfer that can be used in a transaction. Returns the
/// set of debited accounts.
pub fn multi_transfer(
    ctx: &mut Ctx,
    sources: &BTreeMap<(Address, Address), Amount>,
    dests: &BTreeMap<(Address, Address), Amount>,
) -> Result<HashSet<Address>> {
    let debited_accounts = namada_token::multi_transfer(ctx, sources, dests)?;

    let mut evt_sources = BTreeMap::new();
    let mut evt_targets = BTreeMap::new();
    let mut post_balances = BTreeMap::new();

    for ((src, token), amount) in sources {
        // The tx must be authorized by the source address
        ctx.insert_verifier(src)?;
        if token.is_internal() {
            // Established address tokens do not have VPs themselves, their
            // validation is handled by the `Multitoken` internal address, but
            // internal token addresses have to verify the transfer
            ctx.insert_verifier(token)?;
        }
        evt_sources.insert(
            (UserAccount::Internal(src.clone()), token.clone()),
            (*amount).into(),
        );
        post_balances.insert(
            (UserAccount::Internal(src.clone()), token.clone()),
            namada_token::read_balance(ctx, token, src)?.into(),
        );
    }

    for ((dest, token), amount) in dests {
        if token.is_internal() {
            // Established address tokens do not have VPs themselves, their
            // validation is handled by the `Multitoken` internal address, but
            // internal token addresses have to verify the transfer
            ctx.insert_verifier(token)?;
        }
        evt_targets.insert(
            (UserAccount::Internal(dest.clone()), token.clone()),
            (*amount).into(),
        );
        post_balances.insert(
            (UserAccount::Internal(dest.clone()), token.clone()),
            namada_token::read_balance(ctx, token, dest)?.into(),
        );
    }

    ctx.emit(TokenEvent {
        descriptor: "transfer-from-wasm".into(),
        level: EventLevel::Tx,
        operation: TokenOperation::Transfer {
            sources: evt_sources,
            targets: evt_targets,
            post_balances,
        },
    });

    Ok(debited_accounts)
}
