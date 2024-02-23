//! Shielded token storage keys

use masp_primitives::bls12_381::Scalar;
use masp_primitives::sapling::Nullifier;
use namada_core::address::{self, Address};
use namada_core::hash::Hash;
use namada_core::storage::{self, DbKeySeg, KeySeg};
use namada_trans_token::storage_key::parameter_prefix;

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
pub const MASP_LAST_LOCKED_AMOUNT_KEY: &str = "last_locked_ratio";
/// The key for the nominal proportional gain of a shielded pool for a given
/// asset
pub const MASP_KP_GAIN_KEY: &str = "proportional_gain";
/// The key for the nominal derivative gain of a shielded pool for a given asset
pub const MASP_KD_GAIN_KEY: &str = "derivative_gain";
/// The key for the locked ratio target for a given asset
pub const MASP_LOCKED_AMOUNT_TARGET_KEY: &str = "locked_ratio_target";
/// The key for the max reward rate for a given asset
pub const MASP_MAX_REWARD_RATE_KEY: &str = "max_reward_rate";

/// Obtain the nominal proportional key for the given token
pub fn masp_kp_gain_key(token_addr: &Address) -> storage::Key {
    parameter_prefix(token_addr).with_segment(MASP_KP_GAIN_KEY.to_owned())
}

/// Obtain the nominal derivative key for the given token
pub fn masp_kd_gain_key(token_addr: &Address) -> storage::Key {
    parameter_prefix(token_addr).with_segment(MASP_KD_GAIN_KEY.to_owned())
}

/// The max reward rate key for the given token
pub fn masp_max_reward_rate_key(token_addr: &Address) -> storage::Key {
    parameter_prefix(token_addr)
        .with_segment(MASP_MAX_REWARD_RATE_KEY.to_owned())
}

/// Obtain the locked target ratio key for the given token
pub fn masp_locked_amount_target_key(token_addr: &Address) -> storage::Key {
    parameter_prefix(token_addr)
        .with_segment(MASP_LOCKED_AMOUNT_TARGET_KEY.to_owned())
}

/// Obtain the storage key for the last locked ratio of a token
pub fn masp_last_locked_amount_key(token_address: &Address) -> storage::Key {
    parameter_prefix(token_address)
        .with_segment(MASP_LAST_LOCKED_AMOUNT_KEY.to_owned())
}

/// Obtain the storage key for the last inflation of a token
pub fn masp_last_inflation_key(token_address: &Address) -> storage::Key {
    parameter_prefix(token_address)
        .with_segment(MASP_LAST_INFLATION_KEY.to_owned())
}

/// Check if the given storage key is a masp key
pub fn is_masp_key(key: &storage::Key) -> bool {
    matches!(&key.segments[..],
        [DbKeySeg::AddressSeg(addr), ..] if *addr == address::MASP
    )
}
/// Check if the given storage key is allowed to be touched by a masp transfer
pub fn is_masp_allowed_key(key: &storage::Key) -> bool {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(key)]
            if *addr == address::MASP
                && (key.starts_with(PIN_KEY_PREFIX)
                    || key == MASP_NOTE_COMMITMENT_TREE_KEY) =>
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

/// Check if the given storage key is a masp tx pin key
pub fn is_masp_tx_pin_key(key: &storage::Key) -> bool {
    matches!(&key.segments[..],
        [DbKeySeg::AddressSeg(addr),
             DbKeySeg::StringSeg(prefix),
        ] if *addr == address::MASP && prefix.starts_with(PIN_KEY_PREFIX))
}

/// Check if the given storage key is a masp nullifier key
pub fn is_masp_nullifier_key(key: &storage::Key) -> bool {
    matches!(&key.segments[..],
    [DbKeySeg::AddressSeg(addr),
             DbKeySeg::StringSeg(prefix),
             ..
        ] if *addr == address::MASP && prefix == MASP_NULLIFIERS_KEY)
}

/// Get a key for a masp pin
pub fn masp_pin_tx_key(key: &str) -> storage::Key {
    storage::Key::from(address::MASP.to_db_key())
        .push(&(PIN_KEY_PREFIX.to_owned() + key))
        .expect("Cannot obtain a storage key")
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
