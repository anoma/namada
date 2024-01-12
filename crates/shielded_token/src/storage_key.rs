//! Shielded token storage keys

use namada_core::types::address::{self, Address};
use namada_core::types::storage::{self, DbKeySeg};
use namada_trans_token::storage_key::key_of_token;

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
                && (key == HEAD_TX_KEY
                    || key.starts_with(TX_KEY_PREFIX)
                    || key.starts_with(PIN_KEY_PREFIX)
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

/// Check if the given storage key is a masp tx prefix key
pub fn is_masp_tx_prefix_key(key: &storage::Key) -> bool {
    matches!(&key.segments[..],
        [DbKeySeg::AddressSeg(addr),
             DbKeySeg::StringSeg(prefix),
        ] if *addr == address::MASP && prefix.starts_with(TX_KEY_PREFIX))
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
