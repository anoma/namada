//! Transparent token abstract interfaces

use namada_core::address::Address;
use namada_core::storage;
pub use namada_core::token::*;

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
}

/// Abstract token storage read interface
pub trait Read<S> {
    /// Storage error
    type Err;
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
        amount: Amount,
    ) -> Result<(), Self::Err>;

    /// Burn a specified amount of tokens from some address. If the burn amount
    /// is larger than the total balance of the given address, then the
    /// remaining balance is burned. The total supply of the token is
    /// properly adjusted.
    fn burn_tokens(
        storage: &mut S,
        token: &Address,
        source: &Address,
        amount: Amount,
    ) -> Result<(), Self::Err>;

    /// Credit tokens to an account, to be used only by protocol. In
    /// transactions, this would get rejected by the default `vp_token`.
    fn credit_tokens(
        storage: &mut S,
        token: &Address,
        dest: &Address,
        amount: Amount,
    ) -> Result<(), Self::Err>;
}
