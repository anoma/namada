//! Gas storage keys

pub use namada_core::storage::Key;

const ERROR_MSG: &str = "Cannot obtain a valid db key";

/// Get the transaction hash prefix under the `all` subkey
pub fn pred_prefix() -> Key {
    Key::parse("pred/gas").expect(ERROR_MSG)
}

/// Get the full transaction hash prefix under the `last` subkey
pub fn gas_prefix() -> Key {
    Key::parse("gas").expect(ERROR_MSG)
}
