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
pub mod vp;

use std::marker::PhantomData;

use namada_core::address::Address;
use namada_storage::{StorageRead, StorageWrite};
pub use namada_systems::trans_token::*;
pub use storage::*;

/// Transparent token storage `Keys/Read/Write` implementation
#[derive(Debug)]
pub struct Store<S>(PhantomData<S>);

impl<S> Keys for Store<S> {
    fn balance_key(
        token: &Address,
        owner: &Address,
    ) -> namada_core::storage::Key {
        storage_key::balance_key(token, owner)
    }

    fn is_balance_key<'a>(
        token_addr: &Address,
        key: &'a namada_core::storage::Key,
    ) -> Option<&'a Address> {
        storage_key::is_balance_key(token_addr, key)
    }

    fn is_any_token_balance_key(
        key: &namada_core::storage::Key,
    ) -> Option<[&Address; 2]> {
        storage_key::is_any_token_balance_key(key)
    }

    fn minter_key(token_addr: &Address) -> namada_core::storage::Key {
        storage_key::minter_key(token_addr)
    }
}

impl<S> Read<S> for Store<S> where S: StorageRead {}

impl<S> Write<S> for Store<S>
where
    S: StorageWrite + StorageRead,
{
    fn transfer(
        storage: &mut S,
        token: &Address,
        src: &Address,
        dest: &Address,
        amount: Amount,
    ) -> Result<()> {
        storage::transfer(storage, token, src, dest, amount)
    }

    fn burn_tokens(
        storage: &mut S,
        token: &Address,
        source: &Address,
        amount: Amount,
    ) -> Result<()> {
        storage::burn_tokens(storage, token, source, amount)
    }

    fn credit_tokens(
        storage: &mut S,
        token: &Address,
        dest: &Address,
        amount: Amount,
    ) -> Result<()> {
        storage::credit_tokens(storage, token, dest, amount)
    }
}
