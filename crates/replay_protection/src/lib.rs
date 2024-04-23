//! Replay protection storage keys

use namada_core::hash::Hash;
use namada_core::storage::Key;

const ERROR_MSG: &str = "Cannot obtain a valid db key";

/// Get the transaction hash key
pub fn key(hash: &Hash) -> Key {
    Key::parse(hash.to_string()).expect(ERROR_MSG)
}

/// Get the transaction hash prefix under the `current` subkey
pub fn current_prefix() -> Key {
    Key::parse("current").expect(ERROR_MSG)
}

/// Get the transaction hash key under the `current` subkey
pub fn current_key(hash: &Hash) -> Key {
    current_prefix().push(&hash.to_string()).expect(ERROR_MSG)
}
