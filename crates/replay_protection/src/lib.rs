//! Replay protection storage keys

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

use namada_core::address::{Address, InternalAddress};
use namada_core::hash::Hash;
use namada_core::storage::DbKeySeg;
pub use namada_core::storage::Key;

const ERROR_MSG: &str = "Cannot obtain a valid db key";

/// Get the key under which we store a hash which is commitment
/// to all replay protection entries.
pub fn commitment_key() -> Key {
    Key::from(DbKeySeg::AddressSeg(Address::Internal(
        InternalAddress::ReplayProtection,
    )))
    .push(&"commitment".to_string())
    .expect("Should be able to form this key")
}

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
