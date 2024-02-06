use namada_core::address::{Address, InternalAddress};
use namada_core::hints;
use namada_core::token::{self, Amount, DenominatedAmount};
use namada_storage as storage;
use namada_storage::{StorageRead, StorageWrite};

use crate::storage_key::*;

/// Initialize parameters for the token in storage during the genesis block.
pub fn write_params<S>(
    storage: &mut S,
    address: &Address,
) -> storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    storage.write(&minted_balance_key(address), Amount::zero())?;
    Ok(())
}

/// Read the balance of a given token and owner.
pub fn read_balance<S>(
    storage: &S,
    token: &Address,
    owner: &Address,
) -> storage::Result<token::Amount>
where
    S: StorageRead,
{
    let key = balance_key(token, owner);
    let balance = storage.read::<token::Amount>(&key)?.unwrap_or_default();
    Ok(balance)
}

/// Read the total network supply of a given token.
pub fn read_total_supply<S>(
    storage: &S,
    token: &Address,
) -> storage::Result<token::Amount>
where
    S: StorageRead,
{
    let key = minted_balance_key(token);
    let balance = storage.read::<token::Amount>(&key)?.unwrap_or_default();
    Ok(balance)
}

/// Read the denomination of a given token, if any. Note that native
/// transparent tokens do not have this set and instead use the constant
/// [`token::NATIVE_MAX_DECIMAL_PLACES`].
pub fn read_denom<S>(
    storage: &S,
    token: &Address,
) -> storage::Result<Option<token::Denomination>>
where
    S: StorageRead,
{
    let (key, is_default_zero) = match token {
        Address::Internal(InternalAddress::Nut(erc20)) => {
            let token = Address::Internal(InternalAddress::Erc20(*erc20));
            // NB: always use the equivalent ERC20's smallest
            // denomination to specify amounts, if we cannot
            // find a denom in storage
            (denom_key(&token), true)
        }
        Address::Internal(InternalAddress::IbcToken(_)) => {
            return Ok(Some(0u8.into()));
        }
        token => (denom_key(token), false),
    };
    storage.read(&key).map(|opt_denom| {
        Some(opt_denom.unwrap_or_else(|| {
            if is_default_zero {
                0u8.into()
            } else {
                // FIXME: perhaps when we take this branch, we should
                // assume the same behavior as NUTs? maybe this branch
                // is unreachable, anyway. when would regular tokens
                // ever not be denominated?
                hints::cold();
                token::NATIVE_MAX_DECIMAL_PLACES.into()
            }
        }))
    })
}

/// Write the denomination of a given token.
pub fn write_denom<S>(
    storage: &mut S,
    token: &Address,
    denom: token::Denomination,
) -> storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = denom_key(token);
    storage.write(&key, denom)
}

/// Transfer `token` from `src` to `dest`. Returns an `Err` if `src` has
/// insufficient balance or if the transfer the `dest` would overflow (This can
/// only happen if the total supply doesn't fit in `token::Amount`).
pub fn transfer<S>(
    storage: &mut S,
    token: &Address,
    src: &Address,
    dest: &Address,
    amount: token::Amount,
) -> storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    if amount.is_zero() {
        return Ok(());
    }
    let src_key = balance_key(token, src);
    let src_balance = read_balance(storage, token, src)?;
    match src_balance.checked_sub(amount) {
        Some(new_src_balance) => {
            let dest_key = balance_key(token, dest);
            let dest_balance = read_balance(storage, token, dest)?;
            match dest_balance.checked_add(amount) {
                Some(new_dest_balance) => {
                    storage.write(&src_key, new_src_balance)?;
                    storage.write(&dest_key, new_dest_balance)
                }
                None => Err(storage::Error::new_const(
                    "The transfer would overflow destination balance",
                )),
            }
        }
        None => Err(storage::Error::new_const("Insufficient source balance")),
    }
}

/// Credit tokens to an account, to be used only by protocol. In transactions,
/// this would get rejected by the default `vp_token`.
pub fn credit_tokens<S>(
    storage: &mut S,
    token: &Address,
    dest: &Address,
    amount: token::Amount,
) -> storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let balance_key = balance_key(token, dest);
    let cur_balance = read_balance(storage, token, dest)?;
    let new_balance = cur_balance
        .checked_add(amount)
        .ok_or_else(|| storage::Error::new_const("Token balance overflow"))?;

    let total_supply_key = minted_balance_key(token);
    let cur_supply = storage
        .read::<Amount>(&total_supply_key)?
        .unwrap_or_default();
    let new_supply = cur_supply.checked_add(amount).ok_or_else(|| {
        storage::Error::new_const("Token total supply overflow")
    })?;

    storage.write(&balance_key, new_balance)?;
    storage.write(&total_supply_key, new_supply)
}

/// Burn a specified amount of tokens from some address. If the burn amount is
/// larger than the total balance of the given address, then the remaining
/// balance is burned. The total supply of the token is properly adjusted.
pub fn burn_tokens<S>(
    storage: &mut S,
    token: &Address,
    source: &Address,
    amount: token::Amount,
) -> storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let source_balance_key = balance_key(token, source);
    let source_balance = read_balance(storage, token, source)?;

    let amount_to_burn =
        if let Some(new_amount) = source_balance.checked_sub(amount) {
            storage.write(&source_balance_key, new_amount)?;
            amount
        } else {
            storage.write(&source_balance_key, token::Amount::zero())?;
            source_balance
        };

    let old_total_supply = read_total_supply(storage, token)?;
    let new_total_supply = old_total_supply
        .checked_sub(amount_to_burn)
        .ok_or_else(|| {
            storage::Error::new_const("Total token supply underflowed")
        })?;

    let total_supply_key = minted_balance_key(token);
    storage.write(&total_supply_key, new_total_supply)
}

/// Add denomination info if it exists in storage.
pub fn denominated(
    amount: token::Amount,
    token: &Address,
    storage: &impl StorageRead,
) -> storage::Result<DenominatedAmount> {
    let denom = read_denom(storage, token)?.ok_or_else(|| {
        storage::Error::SimpleMessage(
            "No denomination found in storage for the given token",
        )
    })?;
    Ok(DenominatedAmount::new(amount, denom))
}

/// Convert this denominated amount into a plain amount by increasing its
/// precision to the given token's denomination and then taking the
/// significand.
pub fn denom_to_amount(
    denom_amount: DenominatedAmount,
    token: &Address,
    storage: &impl StorageRead,
) -> storage::Result<Amount> {
    let denom = read_denom(storage, token)?.ok_or_else(|| {
        storage::Error::SimpleMessage(
            "No denomination found in storage for the given token",
        )
    })?;
    denom_amount.scale(denom).map_err(storage::Error::new)
}

#[cfg(test)]
mod testing {
    use namada_core::{address, token};
    use namada_storage::testing::TestStorage;

    use super::{burn_tokens, credit_tokens, read_balance, read_total_supply};

    #[test]
    fn test_burn_native_tokens() {
        let mut storage = TestStorage::default();
        let native_token = address::testing::nam();

        // Get some addresses
        let addr1 = address::testing::gen_implicit_address();
        let addr2 = address::testing::gen_implicit_address();
        let addr3 = address::testing::gen_implicit_address();

        let balance1 = token::Amount::native_whole(1);
        let balance2 = token::Amount::native_whole(2);
        let balance3 = token::Amount::native_whole(3);
        let tot_init_balance = balance1 + balance2 + balance3;

        credit_tokens(&mut storage, &native_token, &addr1, balance1).unwrap();
        credit_tokens(&mut storage, &native_token, &addr2, balance2).unwrap();
        credit_tokens(&mut storage, &native_token, &addr3, balance3).unwrap();

        // Check total initial supply
        let total_supply = read_total_supply(&storage, &native_token).unwrap();
        assert_eq!(total_supply, tot_init_balance);

        // Burn some tokens
        let burn1 = token::Amount::from(547_432);
        burn_tokens(&mut storage, &native_token, &addr1, burn1).unwrap();

        // Check new balances
        let addr1_balance =
            read_balance(&storage, &native_token, &addr1).unwrap();
        assert_eq!(addr1_balance, balance1 - burn1);
        let total_supply = read_total_supply(&storage, &native_token).unwrap();
        assert_eq!(total_supply, tot_init_balance - burn1);

        // Burn more tokens from addr1 than it has remaining
        let burn2 = token::Amount::from(1_000_000);
        burn_tokens(&mut storage, &native_token, &addr1, burn2).unwrap();

        // Check new balances
        let addr1_balance =
            read_balance(&storage, &native_token, &addr1).unwrap();
        assert_eq!(addr1_balance, token::Amount::zero());
        let total_supply = read_total_supply(&storage, &native_token).unwrap();
        assert_eq!(total_supply, tot_init_balance - balance1);

        // Burn more tokens from addr2 than are in the total supply
        let burn3 = tot_init_balance + token::Amount::native_whole(1);
        burn_tokens(&mut storage, &native_token, &addr2, burn3).unwrap();

        // Check balances again
        let addr2_balance =
            read_balance(&storage, &native_token, &addr2).unwrap();
        assert_eq!(addr2_balance, token::Amount::zero());
        let total_supply = read_total_supply(&storage, &native_token).unwrap();
        assert_eq!(total_supply, balance3);
    }
}
