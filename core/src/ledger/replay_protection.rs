//! Replay protection storage

use crate::types::hash::Hash;
use crate::types::storage::{DbKeySeg, Key, KeySeg};

/// Replay protection storage root
const STORAGE_ROOT: &str = "replay_protection";

// FIXME: remove the replay protection VP
/// Check if a key is a replay protection key
pub fn is_replay_protection_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::StringSeg(root) if root == STORAGE_ROOT)
}

/// Get the transaction hash key under the last subkey
pub fn get_replay_protection_key(hash: &Hash) -> Key {
    Key::parse(STORAGE_ROOT)
        .expect("Cannot obtain a valid db key")
        .push(&"last".to_string())
        .expect("Cannot obtain a valid db key")
        .push(&hash.to_string())
        .expect("Cannot obtain a valid db key")
}
