use namada_core::address::Address;
use namada_proof_of_stake::token::storage_key::balance_key;
use namada_storage::{Error as StorageError, ResultExt};
pub use namada_token::*;
use namada_tx_env::TxEnv;

use crate::{Ctx, StorageRead, StorageWrite, TxResult};

/// A token transfer that can be used in a transaction.
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

    if amount == Amount::zero() {
        return Ok(());
    }

    let src_key = balance_key(token, src);
    let dest_key = balance_key(token, dest);
    let src_bal: Option<Amount> = ctx.read(&src_key)?;
    let mut src_bal = src_bal
        .ok_or_else(|| StorageError::new_const("the source has no balance"))?;

    if !src_bal.can_spend(&amount) {
        return Err(StorageError::new_const("the source has no enough balance"))
    }

    src_bal.spend(&amount).into_storage_result()?;
    let mut dest_bal: Amount = ctx.read(&dest_key)?.unwrap_or_default();
    dest_bal.receive(&amount).into_storage_result()?;
    ctx.write(&src_key, src_bal)?;
    ctx.write(&dest_key, dest_bal)?;

    Ok(())
}

/// Mint that can be used in a transaction.
pub fn mint(
    ctx: &mut Ctx,
    target: &Address,
    token: &Address,
    amount: Amount,
) -> TxResult {
    credit_tokens(ctx, token, target, amount)
}

/// Burn that can be used in a transaction.
pub fn burn(
    ctx: &mut Ctx,
    target: &Address,
    token: &Address,
    amount: Amount,
) -> TxResult {
    burn_tokens(ctx, &token, &target, amount)
}
