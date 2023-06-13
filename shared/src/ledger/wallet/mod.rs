//! Provides functionality for managing keys and addresses for a user
pub mod alias;
mod keys;
pub mod pre_genesis;
pub mod store;

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::marker::PhantomData;
use std::str::FromStr;

use alias::Alias;
use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::zip32::ExtendedFullViewingKey;
pub use pre_genesis::gen_key_to_store;
pub use store::{gen_sk, AddressVpType, Store};
use thiserror::Error;

pub use self::keys::{DecryptionError, StoredKeypair};
pub use self::store::{ConfirmationResponse, ValidatorData, ValidatorKeys};
use crate::types::address::Address;
use crate::types::key::*;
use crate::types::masp::{
    ExtendedSpendingKey, ExtendedViewingKey, PaymentAddress,
};

/// Captures the interactive parts of the wallet's functioning
pub trait WalletUtils {
    /// The location where the wallet is stored
    type Storage;
    /// Read the password for encryption/decryption from the file/env/stdin.
    /// Panics if all options are empty/invalid.
    fn read_password(prompt_msg: &str) -> String;

    /// Read an alias from the file/env/stdin.
    fn read_alias(prompt_msg: &str) -> String;

    /// The given alias has been selected but conflicts with another alias in
    /// the store. Offer the user to either replace existing mapping, alter the
    /// chosen alias to a name of their chosing, or cancel the aliasing.
    fn show_overwrite_confirmation(
        alias: &Alias,
        alias_for: &str,
    ) -> store::ConfirmationResponse;
}

/// A degenerate implementation of wallet interactivity
pub struct SdkWalletUtils<U>(PhantomData<U>);

impl<U> WalletUtils for SdkWalletUtils<U> {
    type Storage = U;

    fn read_password(_prompt_msg: &str) -> String {
        panic!("attempted to prompt for password in non-interactive mode");
    }

    fn read_alias(_prompt_msg: &str) -> String {
        panic!("attempted to prompt for alias in non-interactive mode");
    }

    fn show_overwrite_confirmation(
        _alias: &Alias,
        _alias_for: &str,
    ) -> store::ConfirmationResponse {
        // Automatically replace aliases in non-interactive mode
        store::ConfirmationResponse::Replace
    }
}

/// The error that is produced when a given key cannot be obtained
#[derive(Error, Debug)]
pub enum FindKeyError {
    /// Could not find a given key in the wallet
    #[error("No matching key found")]
    KeyNotFound,
    /// Could not decrypt a given key in the wallet
    #[error("{0}")]
    KeyDecryptionError(keys::DecryptionError),
}

/// Represents a collection of keys and addresses while caching key decryptions
#[derive(Debug)]
pub struct Wallet<U: WalletUtils> {
    store_dir: U::Storage,
    store: Store,
    decrypted_key_cache: HashMap<Alias, common::SecretKey>,
    decrypted_spendkey_cache: HashMap<Alias, ExtendedSpendingKey>,
}

impl<U: WalletUtils> Wallet<U> {
    /// Create a new wallet from the given backing store and storage location
    pub fn new(store_dir: U::Storage, store: Store) -> Self {
        Self {
            store_dir,
            store,
            decrypted_key_cache: HashMap::default(),
            decrypted_spendkey_cache: HashMap::default(),
        }
    }

    /// Generate a new keypair and derive an implicit address from its public
    /// and insert them into the store with the provided alias, converted to
    /// lower case. If none provided, the alias will be the public key hash (in
    /// lowercase too). If the key is to be encrypted, will prompt for
    /// password from stdin. Stores the key in decrypted key cache and
    /// returns the alias of the key and a reference-counting pointer to the
    /// key.
    pub fn gen_key(
        &mut self,
        scheme: SchemeType,
        alias: Option<String>,
        password: Option<String>,
        force_alias: bool,
    ) -> (String, common::SecretKey) {
        let (alias, key) =
            self.store
                .gen_key::<U>(scheme, alias, password, force_alias);
        // Cache the newly added key
        self.decrypted_key_cache.insert(alias.clone(), key.clone());
        (alias.into(), key)
    }

    /// Generate a spending key and store it under the given alias in the wallet
    pub fn gen_spending_key(
        &mut self,
        alias: String,
        password: Option<String>,
        force_alias: bool,
    ) -> (String, ExtendedSpendingKey) {
        let (alias, key) =
            self.store
                .gen_spending_key::<U>(alias, password, force_alias);
        // Cache the newly added key
        self.decrypted_spendkey_cache.insert(alias.clone(), key);
        (alias.into(), key)
    }

    /// Add validator data to the store
    pub fn add_validator_data(
        &mut self,
        address: Address,
        keys: ValidatorKeys,
    ) {
        self.store.add_validator_data(address, keys);
    }

    /// Returns the validator data, if it exists.
    pub fn get_validator_data(&self) -> Option<&ValidatorData> {
        self.store.get_validator_data()
    }

    /// Returns the validator data, if it exists.  the save function
    /// cannot be called after using this method as it involves a
    /// partial move
    pub fn take_validator_data(&mut self) -> Option<&mut ValidatorData> {
        self.store.validator_data()
    }

    /// Find the stored key by an alias, a public key hash or a public key.
    /// If the key is encrypted and password not supplied, then password will be
    /// interactively prompted. Any keys that are decrypted are stored in and
    /// read from a cache to avoid prompting for password multiple times.
    pub fn find_key(
        &mut self,
        alias_pkh_or_pk: impl AsRef<str>,
        password: Option<String>,
    ) -> Result<common::SecretKey, FindKeyError> {
        // Try cache first
        if let Some(cached_key) = self
            .decrypted_key_cache
            .get(&alias_pkh_or_pk.as_ref().into())
        {
            return Ok(cached_key.clone());
        }
        // If not cached, look-up in store
        let stored_key = self
            .store
            .find_key(alias_pkh_or_pk.as_ref())
            .ok_or(FindKeyError::KeyNotFound)?;
        Self::decrypt_stored_key::<_>(
            &mut self.decrypted_key_cache,
            stored_key,
            alias_pkh_or_pk.into(),
            password,
        )
    }

    /// Find the spending key with the given alias in the wallet and return it.
    /// If the spending key is encrypted but a password is not supplied, then it
    /// will be interactively prompted.
    pub fn find_spending_key(
        &mut self,
        alias: impl AsRef<str>,
        password: Option<String>,
    ) -> Result<ExtendedSpendingKey, FindKeyError> {
        // Try cache first
        if let Some(cached_key) =
            self.decrypted_spendkey_cache.get(&alias.as_ref().into())
        {
            return Ok(*cached_key);
        }
        // If not cached, look-up in store
        let stored_spendkey = self
            .store
            .find_spending_key(alias.as_ref())
            .ok_or(FindKeyError::KeyNotFound)?;
        Self::decrypt_stored_key::<_>(
            &mut self.decrypted_spendkey_cache,
            stored_spendkey,
            alias.into(),
            password,
        )
    }

    /// Find the viewing key with the given alias in the wallet and return it
    pub fn find_viewing_key(
        &mut self,
        alias: impl AsRef<str>,
    ) -> Result<&ExtendedViewingKey, FindKeyError> {
        self.store
            .find_viewing_key(alias.as_ref())
            .ok_or(FindKeyError::KeyNotFound)
    }

    /// Find the payment address with the given alias in the wallet and return
    /// it
    pub fn find_payment_addr(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<&PaymentAddress> {
        self.store.find_payment_addr(alias.as_ref())
    }

    /// Find the stored key by a public key.
    /// If the key is encrypted and password not supplied, then password will be
    /// interactively prompted for. Any keys that are decrypted are stored in
    /// and read from a cache to avoid prompting for password multiple times.
    pub fn find_key_by_pk(
        &mut self,
        pk: &common::PublicKey,
        password: Option<String>,
    ) -> Result<common::SecretKey, FindKeyError> {
        // Try to look-up alias for the given pk. Otherwise, use the PKH string.
        let pkh: PublicKeyHash = pk.into();
        let alias = self
            .store
            .find_alias_by_pkh(&pkh)
            .unwrap_or_else(|| pkh.to_string().into());
        // Try read cache
        if let Some(cached_key) = self.decrypted_key_cache.get(&alias) {
            return Ok(cached_key.clone());
        }
        // Look-up from store
        let stored_key = self
            .store
            .find_key_by_pk(pk)
            .ok_or(FindKeyError::KeyNotFound)?;
        Self::decrypt_stored_key::<_>(
            &mut self.decrypted_key_cache,
            stored_key,
            alias,
            password,
        )
    }

    /// Find the stored key by a public key hash.
    /// If the key is encrypted and password is not supplied, then password will
    /// be interactively prompted for. Any keys that are decrypted are stored in
    /// and read from a cache to avoid prompting for password multiple times.
    pub fn find_key_by_pkh(
        &mut self,
        pkh: &PublicKeyHash,
        password: Option<String>,
    ) -> Result<common::SecretKey, FindKeyError> {
        // Try to look-up alias for the given pk. Otherwise, use the PKH string.
        let alias = self
            .store
            .find_alias_by_pkh(pkh)
            .unwrap_or_else(|| pkh.to_string().into());
        // Try read cache
        if let Some(cached_key) = self.decrypted_key_cache.get(&alias) {
            return Ok(cached_key.clone());
        }
        // Look-up from store
        let stored_key = self
            .store
            .find_key_by_pkh(pkh)
            .ok_or(FindKeyError::KeyNotFound)?;
        Self::decrypt_stored_key::<_>(
            &mut self.decrypted_key_cache,
            stored_key,
            alias,
            password,
        )
    }

    /// Decrypt stored key, if it's not stored un-encrypted.
    /// If a given storage key needs to be decrypted and password is not
    /// supplied, then interactively prompt for password and if successfully
    /// decrypted, store it in a cache.
    fn decrypt_stored_key<
        T: FromStr + Display + BorshSerialize + BorshDeserialize + Clone,
    >(
        decrypted_key_cache: &mut HashMap<Alias, T>,
        stored_key: &StoredKeypair<T>,
        alias: Alias,
        password: Option<String>,
    ) -> Result<T, FindKeyError>
    where
        <T as std::str::FromStr>::Err: Display,
    {
        match stored_key {
            StoredKeypair::Encrypted(encrypted) => {
                let password = password.unwrap_or_else(|| {
                    U::read_password("Enter decryption password: ")
                });
                let key = encrypted
                    .decrypt(password)
                    .map_err(FindKeyError::KeyDecryptionError)?;
                decrypted_key_cache.insert(alias.clone(), key);
                decrypted_key_cache
                    .get(&alias)
                    .cloned()
                    .ok_or(FindKeyError::KeyNotFound)
            }
            StoredKeypair::Raw(raw) => Ok(raw.clone()),
        }
    }

    /// Get all known keys by their alias, paired with PKH, if known.
    pub fn get_keys(
        &self,
    ) -> HashMap<
        String,
        (&StoredKeypair<common::SecretKey>, Option<&PublicKeyHash>),
    > {
        self.store
            .get_keys()
            .into_iter()
            .map(|(alias, value)| (alias.into(), value))
            .collect()
    }

    /// Find the stored address by an alias.
    pub fn find_address(&self, alias: impl AsRef<str>) -> Option<&Address> {
        self.store.find_address(alias)
    }

    /// Find an alias by the address if it's in the wallet.
    pub fn find_alias(&self, address: &Address) -> Option<&Alias> {
        self.store.find_alias(address)
    }

    /// Get all known addresses by their alias, paired with PKH, if known.
    pub fn get_addresses(&self) -> HashMap<String, Address> {
        self.store
            .get_addresses()
            .iter()
            .map(|(alias, value)| (alias.into(), value.clone()))
            .collect()
    }

    /// Get all known payment addresses by their alias
    pub fn get_payment_addrs(&self) -> HashMap<String, PaymentAddress> {
        self.store
            .get_payment_addrs()
            .iter()
            .map(|(alias, value)| (alias.into(), *value))
            .collect()
    }

    /// Get all known viewing keys by their alias
    pub fn get_viewing_keys(&self) -> HashMap<String, ExtendedViewingKey> {
        self.store
            .get_viewing_keys()
            .iter()
            .map(|(alias, value)| (alias.into(), *value))
            .collect()
    }

    /// Get all known viewing keys by their alias
    pub fn get_spending_keys(
        &self,
    ) -> HashMap<String, &StoredKeypair<ExtendedSpendingKey>> {
        self.store
            .get_spending_keys()
            .iter()
            .map(|(alias, value)| (alias.into(), value))
            .collect()
    }

    /// Add a new address with the given alias. If the alias is already used,
    /// will ask whether the existing alias should be replaced, a different
    /// alias is desired, or the alias creation should be cancelled. Return
    /// the chosen alias if the address has been added, otherwise return
    /// nothing.
    pub fn add_address(
        &mut self,
        alias: impl AsRef<str>,
        address: Address,
        force_alias: bool,
    ) -> Option<String> {
        self.store
            .insert_address::<U>(alias.into(), address, force_alias)
            .map(Into::into)
    }

    /// Insert a new key with the given alias. If the alias is already used,
    /// will prompt for overwrite confirmation.
    pub fn insert_keypair(
        &mut self,
        alias: String,
        keypair: StoredKeypair<common::SecretKey>,
        pkh: PublicKeyHash,
        force_alias: bool,
    ) -> Option<String> {
        self.store
            .insert_keypair::<U>(alias.into(), keypair, pkh, force_alias)
            .map(Into::into)
    }

    /// Insert a viewing key into the wallet under the given alias
    pub fn insert_viewing_key(
        &mut self,
        alias: String,
        view_key: ExtendedViewingKey,
        force_alias: bool,
    ) -> Option<String> {
        self.store
            .insert_viewing_key::<U>(alias.into(), view_key, force_alias)
            .map(Into::into)
    }

    /// Insert a spending key into the wallet under the given alias
    pub fn insert_spending_key(
        &mut self,
        alias: String,
        spend_key: StoredKeypair<ExtendedSpendingKey>,
        viewkey: ExtendedViewingKey,
        force_alias: bool,
    ) -> Option<String> {
        self.store
            .insert_spending_key::<U>(
                alias.into(),
                spend_key,
                viewkey,
                force_alias,
            )
            .map(Into::into)
    }

    /// Encrypt the given spending key and insert it into the wallet under the
    /// given alias
    pub fn encrypt_insert_spending_key(
        &mut self,
        alias: String,
        spend_key: ExtendedSpendingKey,
        password: Option<String>,
        force_alias: bool,
    ) -> Option<String> {
        self.store
            .insert_spending_key::<U>(
                alias.into(),
                StoredKeypair::new(spend_key, password).0,
                ExtendedFullViewingKey::from(&spend_key.into()).into(),
                force_alias,
            )
            .map(Into::into)
    }

    /// Insert a payment address into the wallet under the given alias
    pub fn insert_payment_addr(
        &mut self,
        alias: String,
        payment_addr: PaymentAddress,
        force_alias: bool,
    ) -> Option<String> {
        self.store
            .insert_payment_addr::<U>(alias.into(), payment_addr, force_alias)
            .map(Into::into)
    }

    /// Extend this wallet from pre-genesis validator wallet.
    pub fn extend_from_pre_genesis_validator(
        &mut self,
        validator_address: Address,
        validator_alias: Alias,
        other: pre_genesis::ValidatorWallet,
    ) {
        self.store.extend_from_pre_genesis_validator(
            validator_address,
            validator_alias,
            other,
        )
    }

    /// Gets all addresses given a vp_type
    pub fn get_addresses_with_vp_type(
        &self,
        vp_type: AddressVpType,
    ) -> HashSet<Address> {
        self.store.get_addresses_with_vp_type(vp_type)
    }

    /// Add a vp_type to a given address
    pub fn add_vp_type_to_address(
        &mut self,
        vp_type: AddressVpType,
        address: Address,
    ) {
        // defaults to an empty set
        self.store.add_vp_type_to_address(vp_type, address)
    }

    /// Provide immutable access to the backing store
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Provide mutable access to the backing store
    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    /// Access storage location data
    pub fn store_dir(&self) -> &U::Storage {
        &self.store_dir
    }
}
