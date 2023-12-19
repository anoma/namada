//! Transparent token storage keys

use namada_core::types::address::{self, Address, InternalAddress};
use namada_core::types::storage::{self, DbKeySeg, KeySeg};

/// Key segment for a balance key
const BALANCE_STORAGE_KEY: &str = "balance";
/// Key segment for a denomination key
const DENOM_STORAGE_KEY: &str = "denomination";
/// Key segment for multitoken minter
const MINTER_STORAGE_KEY: &str = "minter";
/// Key segment for minted balance
const MINTED_STORAGE_KEY: &str = "minted";

// TODO: move to shielded
/// Key segment for head shielded transaction pointer keys
pub const HEAD_TX_KEY: &str = "head-tx";
/// Key segment prefix for shielded transaction key
pub const TX_KEY_PREFIX: &str = "tx-";
/// Key segment prefix for pinned shielded transactions
pub const PIN_KEY_PREFIX: &str = "pin-";
/// Key segment prefix for the nullifiers
pub const MASP_NULLIFIERS_KEY: &str = "nullifiers";
/// Key segment prefix for the note commitment merkle tree
pub const MASP_NOTE_COMMITMENT_TREE_KEY: &str = "commitment_tree";
/// Key segment prefix for the note commitment anchor
pub const MASP_NOTE_COMMITMENT_ANCHOR_PREFIX: &str = "note_commitment_anchor";
/// Key segment prefix for the convert anchor
pub const MASP_CONVERT_ANCHOR_KEY: &str = "convert_anchor";
/// Last calculated inflation value handed out
pub const MASP_LAST_INFLATION_KEY: &str = "last_inflation";
/// The last locked ratio
pub const MASP_LAST_LOCKED_RATIO_KEY: &str = "last_locked_ratio";
/// The key for the nominal proportional gain of a shielded pool for a given
/// asset
pub const MASP_KP_GAIN_KEY: &str = "proportional_gain";
/// The key for the nominal derivative gain of a shielded pool for a given asset
pub const MASP_KD_GAIN_KEY: &str = "derivative_gain";
/// The key for the locked ratio target for a given asset
pub const MASP_LOCKED_RATIO_TARGET_KEY: &str = "locked_ratio_target";
/// The key for the max reward rate for a given asset
pub const MASP_MAX_REWARD_RATE_KEY: &str = "max_reward_rate";

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

/// Obtain the nominal proportional key for the given token
pub fn masp_kp_gain_key(token_addr: &Address) -> storage::Key {
    key_of_token(token_addr, MASP_KP_GAIN_KEY, "nominal proproitonal gains")
}

/// Obtain the nominal derivative key for the given token
pub fn masp_kd_gain_key(token_addr: &Address) -> storage::Key {
    key_of_token(token_addr, MASP_KD_GAIN_KEY, "nominal proproitonal gains")
}

/// The max reward rate key for the given token
pub fn masp_max_reward_rate_key(token_addr: &Address) -> storage::Key {
    key_of_token(token_addr, MASP_MAX_REWARD_RATE_KEY, "max reward rate")
}

/// Obtain the locked target ratio key for the given token
pub fn masp_locked_ratio_target_key(token_addr: &Address) -> storage::Key {
    key_of_token(
        token_addr,
        MASP_LOCKED_RATIO_TARGET_KEY,
        "nominal proproitonal gains",
    )
}

/// Check if the given storage key is balance key for the given token. If it is,
/// returns the owner. For minted balances, use [`is_any_minted_balance_key()`].
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

/// Check if the given storage key is balance key for unspecified token. If it
/// is, returns the token and owner address.
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

/// Check if the given storage key is a masp key
pub fn is_masp_key(key: &storage::Key) -> bool {
    if key.segments.len() >= 2 {
        matches!(&key.segments[..2],
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)]
            if *addr == address::MASP
                && (key == HEAD_TX_KEY
                    || key.starts_with(TX_KEY_PREFIX)
                    || key.starts_with(PIN_KEY_PREFIX)
                    || key.starts_with(MASP_NULLIFIERS_KEY_PREFIX)))
    } else {
        false
    }
}

/// Check if the given storage key is a masp nullifier key
pub fn is_masp_nullifier_key(key: &storage::Key) -> bool {
    matches!(&key.segments[..],
    [DbKeySeg::AddressSeg(addr),
             DbKeySeg::StringSeg(prefix),
             ..
        ] if *addr == address::MASP && prefix == MASP_NULLIFIERS_KEY_PREFIX)
}

/// Obtain the storage key for the last locked ratio of a token
pub fn masp_last_locked_ratio_key(token_address: &Address) -> storage::Key {
    key_of_token(
        token_address,
        MASP_LAST_LOCKED_RATIO_KEY,
        "cannot obtain storage key for the last locked ratio",
    )
}

/// Obtain the storage key for the last inflation of a token
pub fn masp_last_inflation_key(token_address: &Address) -> storage::Key {
    key_of_token(
        token_address,
        MASP_LAST_INFLATION_KEY,
        "cannot obtain storage key for the last inflation rate",
    )
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
