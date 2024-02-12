//! Replay protection storage

use crate::types::hash::Hash;
use crate::types::storage::Key;

const ERROR_MSG: &str = "Cannot obtain a valid db key";

/// Get the transaction hash prefix under the `all` subkey
pub fn all_prefix() -> Key {
    Key::parse("all").expect(ERROR_MSG)
}

/// Get the transaction hash key under the `all` subkey
pub fn all_key(hash: &Hash) -> Key {
    all_prefix().push(&hash.to_string()).expect(ERROR_MSG)
}

/// Get the full transaction hash prefix under the `last` subkey
pub fn last_prefix() -> Key {
    Key::parse("last").expect(ERROR_MSG)
}

/// Get the full transaction hash key under the `last` subkey
pub fn last_key(hash: &Hash) -> Key {
    last_prefix().push(&hash.to_string()).expect(ERROR_MSG)
}

/// Get the full transaction hash prefix under the `buffer` subkey
pub fn buffer_prefix() -> Key {
    Key::parse("buffer").expect(ERROR_MSG)
}

/// Get the full transaction hash key under the `buffer` subkey
pub fn buffer_key(hash: &Hash) -> Key {
    buffer_prefix().push(&hash.to_string()).expect(ERROR_MSG)
}
