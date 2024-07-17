//! Shielded and transparent tokens related functions

use std::collections::BTreeMap;

use namada_core::address::Address;
use namada_events::extend::UserAccount;
use namada_events::{EmitEvents, EventLevel};
use namada_token::event::{TokenEvent, TokenOperation};
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

/// A transparent token transfer that can be used in a transaction.
pub fn multi_transfer(ctx: &mut Ctx, transfers: &Transfer) -> TxResult {
    let sources = transfers
        .sources
        .clone()
        .into_iter()
        .map(|(account, amount)| {
            ((account.owner, account.token), amount.amount())
        })
        .collect::<BTreeMap<_, _>>();

    let targets = transfers
        .targets
        .clone()
        .into_iter()
        .map(|(account, amount)| {
            ((account.owner, account.token), amount.amount())
        })
        .collect::<BTreeMap<_, _>>();

    namada_token::multi_transfer(ctx, &sources, &targets)?;

    let mut evt_sources = BTreeMap::new();
    let mut evt_targets = BTreeMap::new();
    let mut post_balances = BTreeMap::new();

    for ((src, token), amount) in sources {
        // The tx must be authorized by the source address
        ctx.insert_verifier(&src)?;
        if token.is_internal() {
            // Established address tokens do not have VPs themselves, their
            // validation is handled by the `Multitoken` internal address, but
            // internal token addresses have to verify the transfer
            ctx.insert_verifier(&token)?;
        }
        evt_sources.insert(
            (UserAccount::Internal(src.clone()), token.clone()),
            amount.into(),
        );
        post_balances.insert(
            (UserAccount::Internal(src.clone()), token.clone()),
            namada_token::read_balance(ctx, &token, &src)?.into(),
        );
    }

    for ((dest, token), amount) in targets {
        if token.is_internal() {
            // Established address tokens do not have VPs themselves, their
            // validation is handled by the `Multitoken` internal address, but
            // internal token addresses have to verify the transfer
            ctx.insert_verifier(&token)?;
        }
        evt_targets.insert(
            (UserAccount::Internal(dest.clone()), token.clone()),
            amount.into(),
        );
        post_balances.insert(
            (UserAccount::Internal(dest.clone()), token.clone()),
            namada_token::read_balance(ctx, &token, &dest)?.into(),
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

    Ok(())
}
