use namada_core::ledger::storage_api;
use namada_core::types::address::{Address, InternalAddress};
use namada_core::types::token;

use super::{StorageRead, StorageWrite};

impl token::Parameters {
    /// Initialize parameters for the token in storage during the genesis block.
    pub fn init_storage<DB, H>(
        &self,
        address: &Address,
        wl_storage: &mut ledger_storage::WlStorage<DB, H>,
    ) where
        DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
        H: ledger_storage::StorageHasher,
    {
        let Self {
            max_reward_rate: max_rate,
            kd_gain_nom,
            kp_gain_nom,
            locked_ratio_target: locked_target,
        } = self;
        wl_storage
            .write(&masp_last_inflation_key(address), Amount::zero())
            .expect(
                "last inflation key for the given asset must be initialized",
            );
        wl_storage
            .write(&masp_last_locked_ratio_key(address), Dec::zero())
            .expect(
                "last locked ratio key for the given asset must be initialized",
            );
        wl_storage
            .write(&masp_max_reward_rate_key(address), max_rate)
            .expect("max reward rate for the given asset must be initialized");
        wl_storage
            .write(&masp_locked_ratio_target_key(address), locked_target)
            .expect("locked ratio must be initialized");
        wl_storage
            .write(&masp_kp_gain_key(address), kp_gain_nom)
            .expect("The nominal proportional gain must be initialized");
        wl_storage
            .write(&masp_kd_gain_key(address), kd_gain_nom)
            .expect("The nominal derivative gain must be initialized");
        wl_storage
            .write(&minted_balance_key(address), Amount::zero())
            .expect("The total minted balance key must initialized");
    }
}

/// Read the balance of a given token and owner.
pub fn read_balance<S>(
    storage: &S,
    token: &Address,
    owner: &Address,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    let key = token::balance_key(token, owner);
    let balance = storage.read::<token::Amount>(&key)?.unwrap_or_default();
    Ok(balance)
}

/// Read the total network supply of a given token.
pub fn read_total_supply<S>(
    storage: &S,
    token: &Address,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    let key = token::minted_balance_key(token);
    let balance = storage.read::<token::Amount>(&key)?.unwrap_or_default();
    Ok(balance)
}

/// Read the denomination of a given token, if any. Note that native
/// transparent tokens do not have this set and instead use the constant
/// [`token::NATIVE_MAX_DECIMAL_PLACES`].
pub fn read_denom<S>(
    storage: &S,
    token: &Address,
) -> storage_api::Result<Option<token::Denomination>>
where
    S: StorageRead,
{
    let (key, is_default_zero) = match token {
        Address::Internal(InternalAddress::Nut(erc20)) => {
            let token = Address::Internal(InternalAddress::Erc20(*erc20));
            // NB: always use the equivalent ERC20's smallest
            // denomination to specify amounts, if we cannot
            // find a denom in storage
            (token::denom_key(&token), true)
        }
        Address::Internal(InternalAddress::IbcToken(_)) => {
            return Ok(Some(0u8.into()));
        }
        token => (token::denom_key(token), false),
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
                crate::hints::cold();
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
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = token::denom_key(token);
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
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    if amount.is_zero() {
        return Ok(());
    }
    let src_key = token::balance_key(token, src);
    let src_balance = read_balance(storage, token, src)?;
    match src_balance.checked_sub(amount) {
        Some(new_src_balance) => {
            let dest_key = token::balance_key(token, dest);
            let dest_balance = read_balance(storage, token, dest)?;
            match dest_balance.checked_add(amount) {
                Some(new_dest_balance) => {
                    storage.write(&src_key, new_src_balance)?;
                    storage.write(&dest_key, new_dest_balance)
                }
                None => Err(storage_api::Error::new_const(
                    "The transfer would overflow destination balance",
                )),
            }
        }
        None => {
            Err(storage_api::Error::new_const("Insufficient source balance"))
        }
    }
}

/// Credit tokens to an account, to be used only by protocol. In transactions,
/// this would get rejected by the default `vp_token`.
pub fn credit_tokens<S>(
    storage: &mut S,
    token: &Address,
    dest: &Address,
    amount: token::Amount,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let balance_key = token::balance_key(token, dest);
    let cur_balance = read_balance(storage, token, dest)?;
    let new_balance = cur_balance.checked_add(amount).ok_or_else(|| {
        storage_api::Error::new_const("Token balance overflow")
    })?;

    let total_supply_key = token::minted_balance_key(token);
    let cur_supply = storage
        .read::<Amount>(&total_supply_key)?
        .unwrap_or_default();
    let new_supply = cur_supply.checked_add(amount).ok_or_else(|| {
        storage_api::Error::new_const("Token total supply overflow")
    })?;

    storage.write(&balance_key, new_balance)?;
    storage.write(&total_supply_key, new_supply)
}

/// Burn an amount of token for a specific address.
pub fn burn<S>(
    storage: &mut S,
    token: &Address,
    source: &Address,
    amount: token::Amount,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = token::balance_key(token, source);
    let balance = read_balance(storage, token, source)?;

    let amount_to_burn = match balance.checked_sub(amount) {
        Some(new_balance) => {
            storage.write(&key, new_balance)?;
            amount
        }
        None => {
            storage.write(&key, token::Amount::zero())?;
            balance
        }
    };

    let total_supply = read_total_supply(&*storage, source)?;
    let new_total_supply =
        total_supply.checked_sub(amount_to_burn).unwrap_or_default();

    let total_supply_key = token::minted_balance_key(token);
    storage.write(&total_supply_key, new_total_supply)
}
