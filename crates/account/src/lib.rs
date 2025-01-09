//! Support for signature based authorization of actions on a user account
//! using public key(s) and signature threshold (minimum number of signatures
//! needed to authorize an action) stored on-chain.

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

mod auth;
mod storage;
mod storage_key;
mod types;

pub use auth::AccountPublicKeysMap;
use borsh::{BorshDeserialize, BorshSerialize};
pub use namada_core::address::Address;
pub use namada_core::hash::Hash;
pub use namada_core::key::common;
pub use namada_core::storage::Key;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
pub use storage::*;
pub use storage_key::*;
pub use types::*;

#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
/// Account data structure that holds public keys and signature threshold
/// for multi-signature authorization.
///
/// # Example
/// ```
/// use namada_account::{Account, AccountPublicKeysMap};
/// use namada_core::address::Address;
///
/// let public_keys_map = AccountPublicKeysMap::default();
/// let account = Account {
///     public_keys_map,
///     threshold: 1,
///     address: Address::decode("...").unwrap(),
/// };
/// ```
pub struct Account {
    /// The map between indexes and public keys for an account
    pub public_keys_map: AccountPublicKeysMap,
    /// The minimum number of signatures required to authorize an action
    pub threshold: u8,
    /// The unique address corresponding to the account owner
    pub address: Address,
}

impl Account {
    /// Retrieve a public key by its index in the account's public keys map.
    /// Returns None if the index is not found.
    pub fn get_public_key_from_index(
        &self,
        index: u8,
    ) -> Option<common::PublicKey> {
        self.public_keys_map.get_public_key_from_index(index)
    }

    /// Find the index assigned to a given public key in this account.
    /// Returns None if the public key is not associated with this account.
    pub fn get_index_from_public_key(
        &self,
        public_key: &common::PublicKey,
    ) -> Option<u8> {
        self.public_keys_map.get_index_from_public_key(public_key)
    }

    /// Get a vector containing all public keys associated with this account.
    /// The keys are returned in no particular order.
    pub fn get_all_public_keys(&self) -> Vec<common::PublicKey> {
        self.public_keys_map.pk_to_idx.keys().cloned().collect()
    }
}
