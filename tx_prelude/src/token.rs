use masp_primitives::transaction::Transaction;
use namada_core::types::address::Address;
use namada_core::types::hash::Hash;
use namada_core::types::storage::KeySeg;
use namada_core::types::token;
pub use namada_core::types::token::*;

use super::*;

#[allow(clippy::too_many_arguments)]
/// A token transfer that can be used in a transaction.
pub fn transfer(
    ctx: &mut Ctx,
    src: &Address,
    dest: &Address,
    token: &Address,
    sub_prefix: Option<Address>,
    amount: Amount,
    key: &Option<String>,
    shielded_hash: &Option<Hash>,
    shielded: &Option<Transaction>,
) -> TxResult {
    if amount != Amount::default() {
        let src_key = match &sub_prefix {
            Some(sub_prefix) => token::multitoken_balance_key(sub_prefix, src),
            None => token::balance_key(token, src),
        };
        let dest_key = match &sub_prefix {
            Some(sub_prefix) => token::multitoken_balance_key(sub_prefix, dest),
            None => token::balance_key(token, dest),
        };
        let src_bal: Option<Amount> = ctx.read(&src_key)?;
        let mut src_bal = src_bal.unwrap_or_else(|| {
            log_string(format!("src {} has no balance", src_key));
            unreachable!()
        });
        src_bal.spend(&amount);
        let mut dest_bal: Amount = ctx.read(&dest_key)?.unwrap_or_default();
        dest_bal.receive(&amount);
        if src != dest {
            ctx.write(&src_key, src_bal)?;
            ctx.write(&dest_key, dest_bal)?;
        }
    }

    // If this transaction has a shielded component, then handle it
    // separately
    if let Some(shielded) = shielded {
        let masp_addr = address::masp();
        ctx.insert_verifier(&masp_addr)?;
        let head_tx_key = storage::Key::from(masp_addr.to_db_key())
            .push(&HEAD_TX_KEY.to_owned())
            .expect("Cannot obtain a storage key");
        let current_tx_idx: u64 =
            ctx.read(&head_tx_key).unwrap_or(None).unwrap_or(0);
        let current_tx_key = storage::Key::from(masp_addr.to_db_key())
            .push(&(TX_KEY_PREFIX.to_owned() + &current_tx_idx.to_string()))
            .expect("Cannot obtain a storage key");
        // Save the Transfer object and its location within the blockchain
        // so that clients do not have to separately look these
        // up
        let transfer = Transfer {
            source: src.clone(),
            target: dest.clone(),
            token: token.clone(),
            // todo: build asset types for multitokens
            sub_prefix: None,
            amount,
            key: key.clone(),
            shielded: *shielded_hash,
        };
        let record: (Epoch, BlockHeight, TxIndex, Transfer, Transaction) = (
            ctx.get_block_epoch()?,
            ctx.get_block_height()?,
            ctx.get_tx_index()?,
            transfer,
            shielded.clone(),
        );
        ctx.write(&current_tx_key, record)?;
        ctx.write(&head_tx_key, current_tx_idx + 1)?;
        // If storage key has been supplied, then pin this transaction to it
        if let Some(key) = key {
            let pin_key = storage::Key::from(masp_addr.to_db_key())
                .push(&(PIN_KEY_PREFIX.to_owned() + key))
                .expect("Cannot obtain a storage key");
            ctx.write(&pin_key, current_tx_idx)?;
        }
    }
    Ok(())
}

/// Mint that can be used in a transaction.
pub fn mint(
    ctx: &mut Ctx,
    minter: &Address,
    target: &Address,
    sub_prefix: &Address,
    amount: Amount,
) -> TxResult {
    let target_key = token::multitoken_balance_key(sub_prefix, target);
    let mut target_bal: Amount = ctx.read(&target_key)?.unwrap_or_default();
    target_bal.receive(&amount);

    let minted_key = token::multitoken_minted_key(sub_prefix);
    let mut minted_bal: Amount = ctx.read(&minted_key)?.unwrap_or_default();
    minted_bal.receive(&amount);

    ctx.write(&target_key, target_bal)?;
    ctx.write(&minted_key, minted_bal)?;

    let minter_key = token::multitoken_minter_key(sub_prefix);
    ctx.write(&minter_key, minter)?;

    Ok(())
}

/// Burn that can be used in a transaction.
pub fn burn(
    ctx: &mut Ctx,
    target: &Address,
    sub_prefix: &Address,
    amount: Amount,
) -> TxResult {
    let target_key = token::multitoken_balance_key(sub_prefix, target);
    let mut target_bal: Amount = ctx.read(&target_key)?.unwrap_or_default();
    target_bal.spend(&amount);

    // burn the minted amount
    let minted_key = token::multitoken_minted_key(sub_prefix);
    let mut minted_bal: Amount = ctx.read(&minted_key)?.unwrap_or_default();
    minted_bal.spend(&amount);

    ctx.write(&target_key, target_bal)?;
    ctx.write(&minted_key, minted_bal)?;

    Ok(())
}
