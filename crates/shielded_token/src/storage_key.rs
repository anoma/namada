//! Shielded token storage keys

use masp_primitives::bls12_381::Scalar;
use masp_primitives::sapling::Nullifier;
use namada_core::address::{self, Address};
use namada_core::hash::Hash;
use namada_core::storage::{self, DbKeySeg, KeySeg};
use namada_systems::trans_token;

/// Key segment prefix for the nullifiers
pub const MASP_NULLIFIERS_KEY: &str = "nullifiers";
/// Key segment prefix for the note commitment merkle tree
pub const MASP_NOTE_COMMITMENT_TREE_KEY: &str = "commitment_tree";
/// Key segment prefix for the note commitment anchor
pub const MASP_NOTE_COMMITMENT_ANCHOR_PREFIX: &str = "note_commitment_anchor";
/// Key segment prefix for the convert anchor
pub const MASP_CONVERT_ANCHOR_KEY: &str = "convert_anchor";
/// The key for the token map
pub const MASP_TOKEN_MAP_KEY: &str = "tokens";
/// The key for the asset map
pub const MASP_ASSETS_HASH_KEY: &str = "assets_hash";
/// Last calculated inflation value handed out
pub const MASP_LAST_INFLATION_KEY: &str = "last_inflation";
/// The last locked amount
pub const MASP_LAST_LOCKED_AMOUNT_KEY: &str = "last_locked_amount";
/// The key for the nominal proportional gain of a shielded pool for a given
/// asset
pub const MASP_KP_GAIN_KEY: &str = "proportional_gain";
/// The key for the nominal derivative gain of a shielded pool for a given asset
pub const MASP_KD_GAIN_KEY: &str = "derivative_gain";
/// The key for the locked amount target for a given asset
pub const MASP_LOCKED_AMOUNT_TARGET_KEY: &str = "locked_amount_target";
/// The key for the max reward rate for a given asset
pub const MASP_MAX_REWARD_RATE_KEY: &str = "max_reward_rate";
/// The key for the total inflation rewards minted by MASP
pub const MASP_TOTAL_REWARDS: &str = "max_total_rewards";

/// Obtain the nominal proportional key for the given token
pub fn masp_kp_gain_key<TransToken: trans_token::Keys>(
    token_addr: &Address,
) -> storage::Key {
    TransToken::parameter_prefix(token_addr)
        .with_segment(MASP_KP_GAIN_KEY.to_owned())
}

/// Obtain the nominal derivative key for the given token
pub fn masp_kd_gain_key<TransToken: trans_token::Keys>(
    token_addr: &Address,
) -> storage::Key {
    TransToken::parameter_prefix(token_addr)
        .with_segment(MASP_KD_GAIN_KEY.to_owned())
}

/// The max reward rate key for the given token
pub fn masp_max_reward_rate_key<TransToken: trans_token::Keys>(
    token_addr: &Address,
) -> storage::Key {
    TransToken::parameter_prefix(token_addr)
        .with_segment(MASP_MAX_REWARD_RATE_KEY.to_owned())
}

/// Obtain the locked target amount key for the given token
pub fn masp_locked_amount_target_key<TransToken: trans_token::Keys>(
    token_addr: &Address,
) -> storage::Key {
    TransToken::parameter_prefix(token_addr)
        .with_segment(MASP_LOCKED_AMOUNT_TARGET_KEY.to_owned())
}

/// Obtain the storage key for the last locked amount of a token
pub fn masp_last_locked_amount_key<TransToken: trans_token::Keys>(
    token_address: &Address,
) -> storage::Key {
    TransToken::parameter_prefix(token_address)
        .with_segment(MASP_LAST_LOCKED_AMOUNT_KEY.to_owned())
}

/// Obtain the storage key for the last inflation of a token
pub fn masp_last_inflation_key<TransToken: trans_token::Keys>(
    token_address: &Address,
) -> storage::Key {
    TransToken::parameter_prefix(token_address)
        .with_segment(MASP_LAST_INFLATION_KEY.to_owned())
}

/// Check if the given storage key is a masp key
pub fn is_masp_key(key: &storage::Key) -> bool {
    matches!(&key.segments[..],
        [DbKeySeg::AddressSeg(addr), ..] if *addr == address::MASP
    )
}
/// Check if the given storage key is allowed to be touched by a masp transfer
pub fn is_masp_transfer_key(key: &storage::Key) -> bool {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)]
            if *addr == address::MASP
                && key == MASP_NOTE_COMMITMENT_TREE_KEY =>
        {
            true
        }

        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(key),
            DbKeySeg::StringSeg(_nullifier),
        ] if *addr == address::MASP && key == MASP_NULLIFIERS_KEY => true,
        _ => false,
    }
}

/// Check if the given storage key is a masp nullifier key
pub fn is_masp_nullifier_key(key: &storage::Key) -> bool {
    matches!(&key.segments[..],
    [DbKeySeg::AddressSeg(addr),
             DbKeySeg::StringSeg(prefix),
             ..
        ] if *addr == address::MASP && prefix == MASP_NULLIFIERS_KEY)
}

/// Check if the given key is a masp commitment anchor
pub fn is_masp_commitment_anchor_key(key: &storage::Key) -> bool {
    matches!(&key.segments[..],
    [DbKeySeg::AddressSeg(addr),
             DbKeySeg::StringSeg(prefix),
            ..
        ] if *addr == address::MASP && prefix == MASP_NOTE_COMMITMENT_ANCHOR_PREFIX)
}

/// Check if the given storage key is a masp token map key
pub fn is_masp_token_map_key(key: &storage::Key) -> bool {
    matches!(&key.segments[..],
    [DbKeySeg::AddressSeg(addr),
             DbKeySeg::StringSeg(prefix),
        ] if *addr == address::MASP && prefix == MASP_TOKEN_MAP_KEY)
}

/// Get a key for a masp nullifier
pub fn masp_nullifier_key(nullifier: &Nullifier) -> storage::Key {
    storage::Key::from(address::MASP.to_db_key())
        .push(&MASP_NULLIFIERS_KEY.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&Hash(nullifier.0))
        .expect("Cannot obtain a storage key")
}

/// Get the key for the masp commitment tree
pub fn masp_commitment_tree_key() -> storage::Key {
    storage::Key::from(address::MASP.to_db_key())
        .push(&MASP_NOTE_COMMITMENT_TREE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get a key for a masp commitment tree anchor
pub fn masp_commitment_anchor_key(anchor: impl Into<Scalar>) -> storage::Key {
    storage::Key::from(address::MASP.to_db_key())
        .push(&MASP_NOTE_COMMITMENT_ANCHOR_PREFIX.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&Hash(anchor.into().to_bytes()))
        .expect("Cannot obtain a storage key")
}

/// Get the key for the masp convert tree anchor
pub fn masp_convert_anchor_key() -> storage::Key {
    storage::Key::from(address::MASP.to_db_key())
        .push(&MASP_CONVERT_ANCHOR_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get the key for the masp token map
pub fn masp_token_map_key() -> storage::Key {
    storage::Key::from(address::MASP.to_db_key())
        .push(&MASP_TOKEN_MAP_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get the key for the masp assets' hash
pub fn masp_assets_hash_key() -> storage::Key {
    storage::Key::from(address::MASP.to_db_key())
        .push(&MASP_ASSETS_HASH_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// The max reward rate key for the given token
pub fn masp_total_rewards() -> storage::Key {
    storage::Key::from(address::MASP.to_db_key())
        .push(&MASP_TOTAL_REWARDS.to_owned())
        .expect("Cannot obtain a storage key")
}
