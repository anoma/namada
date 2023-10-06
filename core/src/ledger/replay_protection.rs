//! Replay protection storage

use crate::types::hash::Hash;
use crate::types::storage::Key;

const ERROR_MSG: &str = "Cannot obtain a valid db key";

/// Get the transaction hash key under the `last` subkey
pub fn get_replay_protection_last_subkey(hash: &Hash) -> Key {
    Key::parse("last")
        .expect(ERROR_MSG)
        .push(&hash.to_string())
        .expect(ERROR_MSG)
}

/// Get the transaction hash key under the `all` subkey
pub fn get_replay_protection_all_subkey(hash: &Hash) -> Key {
    Key::parse("all")
        .expect(ERROR_MSG)
        .push(&hash.to_string())
        .expect(ERROR_MSG)
}

/// Get the full transaction hash key under the `last` subkey
pub fn get_replay_protection_last_key(hash: &Hash) -> Key {
    Key::parse("replay_protection")
        .expect(ERROR_MSG)
        .push(&"last".to_string())
        .expect(ERROR_MSG)
        .push(&hash.to_string())
        .expect(ERROR_MSG)
}
