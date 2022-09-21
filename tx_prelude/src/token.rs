use namada::types::address::{Address, InternalAddress};
use namada::types::token;
pub use namada::types::token::*;

use super::*;

/// A token transfer that can be used in a transaction.
pub fn transfer(
    ctx: &mut Ctx,
    src: &Address,
    dest: &Address,
    token: &Address,
    sub_prefix: Option<storage::Key>,
    amount: Amount,
) -> TxResult {
    let src_key = match &sub_prefix {
        Some(sub_prefix) => {
            let prefix = token::multitoken_balance_prefix(token, sub_prefix);
            token::multitoken_balance_key(&prefix, src)
        }
        None => token::balance_key(token, src),
    };
    let dest_key = match &sub_prefix {
        Some(sub_prefix) => {
            let prefix = token::multitoken_balance_prefix(token, sub_prefix);
            token::multitoken_balance_key(&prefix, dest)
        }
        None => token::balance_key(token, dest),
    };
    let src_bal: Option<Amount> = match src {
        Address::Internal(InternalAddress::IbcMint) => Some(Amount::max()),
        Address::Internal(InternalAddress::IbcBurn) => {
            log_string("invalid transfer from the burn address");
            unreachable!()
        }
        _ => ctx.read(&src_key)?,
    };
    let mut src_bal = src_bal.unwrap_or_else(|| {
        log_string(format!("src {} has no balance", src_key));
        unreachable!()
    });
    src_bal.spend(&amount);
    let mut dest_bal: Amount = match dest {
        Address::Internal(InternalAddress::IbcMint) => {
            log_string("invalid transfer to the mint address");
            unreachable!()
        }
        _ => ctx.read(&dest_key)?.unwrap_or_default(),
    };
    dest_bal.receive(&amount);
    match src {
        Address::Internal(InternalAddress::IbcMint) => {
            ctx.write_temp(&src_key, src_bal)?;
        }
        Address::Internal(InternalAddress::IbcBurn) => unreachable!(),
        _ => {
            ctx.write(&src_key, src_bal)?;
        }
    }
    match dest {
        Address::Internal(InternalAddress::IbcMint) => unreachable!(),
        Address::Internal(InternalAddress::IbcBurn) => {
            ctx.write_temp(&dest_key, dest_bal)?;
        }
        _ => {
            ctx.write(&dest_key, dest_bal)?;
        }
    }
    Ok(())
}

/// A token transfer with storage keys that can be used in a transaction.
pub fn transfer_with_keys(
    ctx: &mut Ctx,
    src_key: &storage::Key,
    dest_key: &storage::Key,
    amount: Amount,
) -> TxResult {
    let src_owner = is_any_multitoken_balance_key(src_key).map(|(_, o)| o);
    let src_bal: Option<Amount> = match src_owner {
        Some(Address::Internal(InternalAddress::IbcMint)) => {
            Some(Amount::max())
        }
        Some(Address::Internal(InternalAddress::IbcBurn)) => {
            log_string("invalid transfer from the burn address");
            unreachable!()
        }
        Some(_) => ctx.read(src_key)?,
        None => {
            // the key is not a multitoken key
            match is_any_token_balance_key(src_key) {
                Some(_) => ctx.read(src_key)?,
                None => {
                    log_string(format!("invalid balance key: {}", src_key));
                    unreachable!()
                }
            }
        }
    };
    let mut src_bal = src_bal.unwrap_or_else(|| {
        log_string(format!("src {} has no balance", src_key));
        unreachable!()
    });
    src_bal.spend(&amount);
    let dest_owner = is_any_multitoken_balance_key(dest_key).map(|(_, o)| o);
    let mut dest_bal: Amount = match dest_owner {
        Some(Address::Internal(InternalAddress::IbcMint)) => {
            log_string("invalid transfer to the mint address");
            unreachable!()
        }
        Some(_) => ctx.read(dest_key)?.unwrap_or_default(),
        None => match is_any_token_balance_key(dest_key) {
            Some(_) => ctx.read(dest_key)?.unwrap_or_default(),
            None => {
                log_string(format!("invalid balance key: {}", dest_key));
                unreachable!()
            }
        },
    };
    dest_bal.receive(&amount);
    match src_owner {
        Some(Address::Internal(InternalAddress::IbcMint)) => {
            ctx.write_temp(src_key, src_bal)?;
        }
        _ => ctx.write(src_key, src_bal)?,
    }
    match dest_owner {
        Some(Address::Internal(InternalAddress::IbcBurn)) => {
            ctx.write_temp(dest_key, dest_bal)?;
        }
        _ => ctx.write(dest_key, dest_bal)?,
    }
    Ok(())
}
