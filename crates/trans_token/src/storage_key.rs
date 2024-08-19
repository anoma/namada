//! Transparent token storage keys

use namada_core::address::{Address, InternalAddress};
use namada_core::storage::{self, DbKeySeg, KeySeg};

/// Key segment for a balance key
pub const BALANCE_STORAGE_KEY: &str = "balance";
/// Key segment for a denomination key
pub const DENOM_STORAGE_KEY: &str = "denomination";
/// Key segment for multitoken minter
pub const MINTER_STORAGE_KEY: &str = "minter";
/// Key segment for minted balance
pub const MINTED_STORAGE_KEY: &str = "minted";
/// Key segment for token parameters
pub const PARAMETERS_STORAGE_KEY: &str = "parameters";

/// Gets the key for the given token address, error with the given
/// message to expect if the key is not in the address
pub fn key_of_token(
    token_addr: &Address,
    specific_key: &str,
    expect_message: &str,
) -> storage::Key {
    storage::Key::from(token_addr.to_db_key())
        .push(&specific_key.to_owned())
        .expect(expect_message)
}

/// Obtain a storage key for user's balance.
pub fn balance_key(token_addr: &Address, owner: &Address) -> storage::Key {
    balance_prefix(token_addr)
        .push(&owner.to_db_key())
        .expect("Cannot obtain a storage key")
}

/// Obtain a storage key prefix for all users' balances.
pub fn balance_prefix(token_addr: &Address) -> storage::Key {
    storage::Key::from(
        Address::Internal(InternalAddress::Multitoken).to_db_key(),
    )
    .push(&token_addr.to_db_key())
    .expect("Cannot obtain a storage key")
    .push(&BALANCE_STORAGE_KEY.to_owned())
    .expect("Cannot obtain a storage key")
}

/// Obtain a storage key prefix for token parameters.
pub fn parameter_prefix(token_addr: &Address) -> storage::Key {
    storage::Key::from(
        Address::Internal(InternalAddress::Multitoken).to_db_key(),
    )
    .push(&token_addr.to_db_key())
    .expect("Cannot obtain a storage key")
    .push(&PARAMETERS_STORAGE_KEY.to_owned())
    .expect("Cannot obtain a storage key")
}

/// Obtain a storage key for the multitoken minter.
pub fn minter_key(token_addr: &Address) -> storage::Key {
    storage::Key::from(
        Address::Internal(InternalAddress::Multitoken).to_db_key(),
    )
    .push(&token_addr.to_db_key())
    .expect("Cannot obtain a storage key")
    .push(&MINTER_STORAGE_KEY.to_owned())
    .expect("Cannot obtain a storage key")
}

/// Obtain a storage key for the minted multitoken balance.
pub fn minted_balance_key(token_addr: &Address) -> storage::Key {
    balance_prefix(token_addr)
        .push(&MINTED_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Check if a key is part of the multitoken vp sub storage
pub fn is_multitoken_key(key: &storage::Key) -> bool {
    match key.fst_address() {
        Some(addr) => addr.eq(&Address::Internal(InternalAddress::Multitoken)),
        None => false,
    }
}

/// Check if the given storage key is a balance key for the given token. If it
/// is, return the owner. For minted balances, use
/// [`is_any_minted_balance_key()`].
pub fn is_balance_key<'a>(
    token_addr: &Address,
    key: &'a storage::Key,
) -> Option<&'a Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::AddressSeg(token),
            DbKeySeg::StringSeg(balance),
            DbKeySeg::AddressSeg(owner),
        ] if *addr == Address::Internal(InternalAddress::Multitoken)
            && token == token_addr
            && balance == BALANCE_STORAGE_KEY =>
        {
            Some(owner)
        }
        _ => None,
    }
}

/// Check if the given storage key is a parameter key for an unspecified token.
/// If it is, return the token address.
pub fn is_any_token_parameter_key(key: &storage::Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::AddressSeg(token),
            DbKeySeg::StringSeg(parameter),
            DbKeySeg::StringSeg(_parameter_name),
        ] if *addr == Address::Internal(InternalAddress::Multitoken)
            && parameter == PARAMETERS_STORAGE_KEY =>
        {
            Some(token)
        }
        _ => None,
    }
}

/// Check if the given storage key is a balance key for an unspecified token. If
/// it is, return the token and owner address.
pub fn is_any_token_balance_key(key: &storage::Key) -> Option<[&Address; 2]> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::AddressSeg(token),
            DbKeySeg::StringSeg(balance),
            DbKeySeg::AddressSeg(owner),
        ] if *addr == Address::Internal(InternalAddress::Multitoken)
            && balance == BALANCE_STORAGE_KEY =>
        {
            Some([token, owner])
        }
        _ => None,
    }
}

/// Obtain a storage key denomination of a token.
pub fn denom_key(token_addr: &Address) -> storage::Key {
    storage::Key::from(token_addr.to_db_key())
        .push(&DENOM_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Check if the given storage key is a denomination key for the given token.
pub fn is_denom_key(token_addr: &Address, key: &storage::Key) -> bool {
    matches!(&key.segments[..],
        [
            DbKeySeg::AddressSeg(addr),
            ..,
            DbKeySeg::StringSeg(key),
        ] if key == DENOM_STORAGE_KEY && addr == token_addr)
}

/// Check if the given storage key is for a minter of a unspecified token.
/// If it is, returns the token.
pub fn is_any_minter_key(key: &storage::Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::AddressSeg(token),
            DbKeySeg::StringSeg(minter),
        ] if *addr == Address::Internal(InternalAddress::Multitoken)
            && minter == MINTER_STORAGE_KEY =>
        {
            Some(token)
        }
        _ => None,
    }
}

/// Check if the given storage key is for total supply of a unspecified token.
/// If it is, returns the token.
pub fn is_any_minted_balance_key(key: &storage::Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::AddressSeg(token),
            DbKeySeg::StringSeg(balance),
            DbKeySeg::StringSeg(owner),
        ] if *addr == Address::Internal(InternalAddress::Multitoken)
            && balance == BALANCE_STORAGE_KEY
            && owner == MINTED_STORAGE_KEY =>
        {
            Some(token)
        }
        _ => None,
    }
}
