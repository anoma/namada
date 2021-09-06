pub mod defaults;
mod keys;
mod store;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anoma::types::address::Address;
use anoma::types::key::ed25519::{PublicKey, PublicKeyHash};
use thiserror::Error;

pub use self::keys::{DecryptedKeypair, DecryptionError, StoredKeypair};
use self::store::{Alias, Store};
use crate::cli;

#[derive(Debug)]
pub struct Wallet {
    base_dir: PathBuf,
    store: Store,
}

#[derive(Error, Debug)]
pub enum FindKeyError {
    #[error("No matching key found")]
    KeyNotFound,
    #[error("{0}")]
    KeyDecryptionError(keys::DecryptionError),
}

impl Wallet {
    /// Load a wallet from the store file or create a new one with the default
    /// keys and addresses if not found.
    pub fn load_or_new(base_dir: &Path) -> Self {
        let store = Store::load_or_new(base_dir).unwrap_or_else(|err| {
            eprintln!("Unable to load the wallet: {}", err);
            cli::safe_exit(1)
        });
        Self {
            base_dir: base_dir.to_path_buf(),
            store,
        }
    }

    /// Save the wallet store to a file.
    pub fn save(&self) -> std::io::Result<()> {
        self.store.save(&self.base_dir)
    }

    /// Generate a new keypair and derive an implicit address from its public
    /// and insert them into the store with the provided alias. If none
    /// provided, the alias will be the public key hash. If the key is to be
    /// encrypted, will prompt for password from stdin. Returns the alias of
    /// the key.
    pub fn gen_key(
        &mut self,
        alias: Option<String>,
        unsafe_dont_encrypt: bool,
    ) -> String {
        let password = if unsafe_dont_encrypt {
            println!("Warning: The keypair will NOT be encrypted.");
            None
        } else {
            Some(read_password("Enter encryption password: "))
        };
        self.store.gen_key(alias, password)
    }

    /// Find the stored key by an alias, a public key hash or a public key.
    /// If the key is encrypted, will prompt for password from stdin.
    pub fn find_key(
        &self,
        alias_pkh_or_pk: impl AsRef<str>,
    ) -> Result<DecryptedKeypair, FindKeyError> {
        let stored_key = self
            .store
            .find_key(alias_pkh_or_pk)
            .ok_or(FindKeyError::KeyNotFound)?;
        stored_key
            .get(true)
            .map_err(FindKeyError::KeyDecryptionError)
    }

    /// Find the stored key by a public key.
    /// If the key is encrypted, will prompt for password from stdin.
    pub fn find_key_by_pk(
        &self,
        pk: &PublicKey,
    ) -> Result<DecryptedKeypair, FindKeyError> {
        let stored_key = self
            .store
            .find_key_by_pk(pk)
            .ok_or(FindKeyError::KeyNotFound)?;
        stored_key
            .get(true)
            .map_err(FindKeyError::KeyDecryptionError)
    }

    /// Find the stored key by a public key hash.
    /// If the key is encrypted, will prompt for password from stdin.
    pub fn find_key_by_pkh(
        &self,
        pkh: &PublicKeyHash,
    ) -> Result<DecryptedKeypair, FindKeyError> {
        let stored_key = self
            .store
            .find_key_by_pkh(pkh)
            .ok_or(FindKeyError::KeyNotFound)?;
        stored_key
            .get(true)
            .map_err(FindKeyError::KeyDecryptionError)
    }

    /// Get all known keys by their alias, paired with PKH, if known.
    pub fn get_keys(
        &self,
    ) -> HashMap<Alias, (&StoredKeypair, Option<&PublicKeyHash>)> {
        self.store.get_keys()
    }

    /// Find the stored address by an alias.
    pub fn find_address(&self, alias: impl AsRef<str>) -> Option<&Address> {
        self.store.find_address(alias)
    }

    /// Get all known addresses by their alias, paired with PKH, if known.
    pub fn get_addresses(&self) -> &HashMap<Alias, Address> {
        self.store.get_addresses()
    }

    /// Add a new address with the given alias. If the alias is already used,
    /// will prompt for overwrite confirmation, which when declined, the address
    /// won't be added. Return `true` if the address has been added.
    pub fn add_address(&mut self, alias: String, address: Address) -> bool {
        self.store.insert_address(alias, address)
    }
}

/// Read the password for encryption/decryption from the stdin. Panics if the
/// input is an empty string.
fn read_password(prompt_msg: &str) -> String {
    let pwd =
        rpassword::read_password_from_tty(Some(prompt_msg)).unwrap_or_default();
    if pwd.is_empty() {
        eprintln!("Password cannot be empty");
        cli::safe_exit(1)
    }
    pwd
}
