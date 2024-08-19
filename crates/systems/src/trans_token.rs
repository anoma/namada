//! Transparent token abstract interfaces

use std::borrow::Cow;

use namada_core::address::Address;
pub use namada_core::token::*;
use namada_core::{storage, token};
pub use namada_storage::Result;

/// Abstract token keys interface
pub trait Keys {
    /// Key for transparent token balance
    fn balance_key(token: &Address, owner: &Address) -> storage::Key;

    /// Returns the owner address if the given storage key is a balance key for
    /// the given token.
    fn is_balance_key<'a>(
        token_addr: &Address,
        key: &'a storage::Key,
    ) -> Option<&'a Address>;

    /// Check if the given storage key is a balance key for an unspecified
    /// token. If it is, return the token and owner address.
    fn is_any_token_balance_key(key: &storage::Key) -> Option<[&Address; 2]>;

    /// Obtain a storage key for the multitoken minter.
    fn minter_key(token_addr: &Address) -> storage::Key;

    /// Obtain a storage key prefix for token parameters.
    fn parameter_prefix(token_addr: &Address) -> storage::Key;

    /// Obtain a storage key for the minted multitoken balance.
    fn minted_balance_key(token_addr: &Address) -> storage::Key;

    /// Check if the given storage key is for total supply of a unspecified
    /// token. If it is, returns the token.
    fn is_any_minted_balance_key(key: &storage::Key) -> Option<&Address>;
}

/// Abstract token storage read interface
pub trait Read<S> {
    /// Read the denomination of a given token, if any. Note that native
    /// transparent tokens do not have this set and instead use the constant
    /// [`token::NATIVE_MAX_DECIMAL_PLACES`].
    fn read_denom(
        storage: &S,
        token: &Address,
    ) -> Result<Option<token::Denomination>>;

    /// Get the effective circulating total supply of native tokens.
    fn get_effective_total_native_supply(storage: &S) -> Result<token::Amount>;

    /// Read the balance of a given token and owner.
    fn read_balance(
        storage: &S,
        token: &Address,
        owner: &Address,
    ) -> Result<token::Amount>;
}

/// Abstract token storage write interface
pub trait Write<S>: Read<S> {
    /// Transfer `token` from `src` to `dest`. Returns an `Err` if `src` has
    /// insufficient balance or if the transfer the `dest` would overflow (This
    /// can only happen if the total supply doesn't fit in `token::Amount`).
    fn transfer(
        storage: &mut S,
        token: &Address,
        src: &Address,
        dest: &Address,
        amount: token::Amount,
    ) -> Result<()>;

    /// Burn a specified amount of tokens from some address. If the burn amount
    /// is larger than the total balance of the given address, then the
    /// remaining balance is burned. The total supply of the token is
    /// properly adjusted.
    fn burn_tokens(
        storage: &mut S,
        token: &Address,
        source: &Address,
        amount: token::Amount,
    ) -> Result<()>;

    /// Credit tokens to an account, to be used only by protocol. In
    /// transactions, this would get rejected by the default `vp_token`.
    fn credit_tokens(
        storage: &mut S,
        token: &Address,
        dest: &Address,
        amount: token::Amount,
    ) -> Result<()>;
}

/// Abstract token events interface
pub trait Events<S>: Read<S> {
    /// Emit mint token event
    fn emit_mint_event(
        storage: &mut S,
        descriptor: Cow<'static, str>,
        token: &Address,
        amount: token::Amount,
        target: &Address,
    ) -> Result<()>;

    /// Emit burn token event
    fn emit_burn_event(
        storage: &mut S,
        descriptor: Cow<'static, str>,
        token: &Address,
        amount: token::Amount,
        target: &Address,
    ) -> Result<()>;
}
