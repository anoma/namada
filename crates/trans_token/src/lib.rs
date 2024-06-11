//! Transparent token types, storage functions, and validation.

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

pub mod event;
mod storage;
pub mod storage_key;

use std::marker::PhantomData;

use namada_core::address::Address;
pub use namada_core::token::*;
pub use storage::*;

/// Transparent token storage `Keys/Read/Write` implementation
#[derive(Debug)]
pub struct Store<S>(PhantomData<S>);

impl<S> Keys for Store<S> {
    fn balance(token: &Address, owner: &Address) -> namada_core::storage::Key {
        storage_key::balance_key(token, owner)
    }

    fn is_balance<'a>(
        token_addr: &Address,
        key: &'a namada_core::storage::Key,
    ) -> Option<&'a Address> {
        storage_key::is_balance_key(token_addr, key)
    }
}
