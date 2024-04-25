//! Provides functionality for managing keys and addresses for a user
pub mod alias;
mod derivation_path;
mod keys;
pub mod pre_genesis;
pub mod store;

use std::collections::BTreeMap;
use std::fmt::Display;
use std::str::FromStr;

use alias::Alias;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::address::Address;
use namada_core::collections::{HashMap, HashSet};
use namada_core::ibc::is_ibc_denom;
use namada_core::key::*;
use namada_core::masp::{
    ExtendedSpendingKey, ExtendedViewingKey, PaymentAddress,
};
pub use pre_genesis::gen_key_to_store;
use rand::CryptoRng;
use rand_core::RngCore;
pub use store::{AddressVpType, Store};
use thiserror::Error;
use zeroize::Zeroizing;

pub use self::derivation_path::{DerivationPath, DerivationPathError};
pub use self::keys::{DecryptionError, StoredKeypair};
pub use self::store::{ConfirmationResponse, ValidatorData, ValidatorKeys};
use crate::wallet::store::{derive_hd_secret_key, derive_hd_spending_key};

/// Captures the interactive parts of the wallet's functioning
pub trait WalletIo: Sized + Clone {
    /// Secure random number generator
    type Rng: RngCore;

    /// Generates a random mnemonic of the given mnemonic type.
    fn generate_mnemonic_code(
        mnemonic_type: MnemonicType,
        rng: &mut Self::Rng,
    ) -> Mnemonic {
        const BITS_PER_BYTE: usize = 8;

        // generate random mnemonic
        let entropy_size = mnemonic_type.entropy_bits() / BITS_PER_BYTE;
        let mut bytes = vec![0u8; entropy_size];
        rand::RngCore::fill_bytes(rng, &mut bytes);
        Mnemonic::from_entropy(&bytes, Language::English)
            .expect("Mnemonic creation should not fail")
    }

    /// Read the password for decryption from the file/env/stdin.
    fn read_password(_confirm: bool) -> Zeroizing<String> {
        panic!("attempted to prompt for password in non-interactive mode");
    }

    /// Read an alias from the file/env/stdin.
    fn read_alias(_prompt_msg: &str) -> String {
        panic!("attempted to prompt for alias in non-interactive mode");
    }

    /// Read mnemonic code from the file/env/stdin.
    fn read_mnemonic_code() -> Option<Mnemonic> {
        panic!("attempted to prompt for alias in non-interactive mode");
    }

    /// Read a mnemonic code from the file/env/stdin.
    fn read_mnemonic_passphrase(_confirm: bool) -> Zeroizing<String> {
        panic!("attempted to prompt for alias in non-interactive mode");
    }

    /// The given alias has been selected but conflicts with another alias in
    /// the store. Offer the user to either replace existing mapping, alter the
    /// chosen alias to a name of their choice, or cancel the aliasing.
    fn show_overwrite_confirmation(
        _alias: &Alias,
        _alias_for: &str,
    ) -> store::ConfirmationResponse {
        // Automatically replace aliases in non-interactive mode
        store::ConfirmationResponse::Replace
    }
}

/// Errors of wallet loading and storing
#[derive(Error, Debug, Clone)]
pub enum LoadStoreError {
    /// Wallet store decoding error
    #[error("Failed decoding the wallet store: {0}")]
    Decode(toml::de::Error),
    /// Wallet store reading error
    #[error("Failed to read the wallet store from {0}: {1}")]
    ReadWallet(String, String),
    /// Wallet store writing error
    #[error("Failed to write the wallet store: {0}")]
    StoreNewWallet(String),
    /// Wallet store update error
    #[error("Failed to update the wallet store from {0}: {1}")]
    UpdateWallet(String, String),
}

/// Captures the permanent storage parts of the wallet's functioning
pub trait WalletStorage: Sized + Clone {
    /// Save the wallet store to a file.
    fn save<U>(&self, wallet: &Wallet<U>) -> Result<(), LoadStoreError>;

    /// Load a wallet from the store file.
    fn load<U>(&self, wallet: &mut Wallet<U>) -> Result<(), LoadStoreError>;

    /// Load store into memory
    fn load_in_mem<U>(
        &self,
        wallet: &mut Wallet<U>,
    ) -> Result<(), LoadStoreError>;

    /// Atomically update the wallet store
    fn update_store(
        &self,
        update: impl FnOnce(&mut Store),
    ) -> Result<(), LoadStoreError>;

    /// Load wallet from the store file (read only)
    fn load_store_read_only(&self) -> Result<Store, LoadStoreError>;

    // fn close<U>(&self, wallet: &Wallet<U>, storage_lock: WalletStorageLock)
    // -> Result<(), LoadStoreError>;
}

#[cfg(feature = "std")]
/// Implementation of wallet functionality depending on a standard filesystem
pub mod fs {
    use std::fs;
    use std::io::{Read, Write};
    use std::path::PathBuf;

    use fd_lock::RwLock;
    use rand_core::OsRng;

    use super::*;

    /// A trait for deriving WalletStorage for standard filesystems
    pub trait FsWalletStorage: Clone {
        /// The directory in which the wallet is supposed to be stored
        fn store_dir(&self) -> &PathBuf;
    }

    /// Wallet file name
    const FILE_NAME: &str = "wallet.toml";

    impl<F: FsWalletStorage> WalletStorage for F {
        fn save<U>(&self, wallet: &Wallet<U>) -> Result<(), LoadStoreError> {
            let data = wallet.store.encode();
            let wallet_path = self.store_dir().join(FILE_NAME);
            // Make sure the dir exists
            let wallet_dir = wallet_path.parent().unwrap();
            fs::create_dir_all(wallet_dir).map_err(|err| {
                LoadStoreError::StoreNewWallet(err.to_string())
            })?;
            // Write the file
            let mut options = fs::OpenOptions::new();
            options.create(true).write(true).truncate(true);
            let mut lock =
                RwLock::new(options.open(wallet_path).map_err(|err| {
                    LoadStoreError::StoreNewWallet(err.to_string())
                })?);
            let mut guard = lock.write().map_err(|err| {
                LoadStoreError::StoreNewWallet(err.to_string())
            })?;
            guard
                .write_all(&data)
                .map_err(|err| LoadStoreError::StoreNewWallet(err.to_string()))
        }

        fn load<U>(
            &self,
            wallet: &mut Wallet<U>,
        ) -> Result<(), LoadStoreError> {
            let wallet_file = self.store_dir().join(FILE_NAME);
            let mut options = fs::OpenOptions::new();
            options.read(true).write(false);
            let lock =
                RwLock::new(options.open(&wallet_file).map_err(|err| {
                    LoadStoreError::ReadWallet(
                        wallet_file.to_string_lossy().into_owned(),
                        err.to_string(),
                    )
                })?);
            let guard = lock.read().map_err(|err| {
                LoadStoreError::ReadWallet(
                    wallet_file.to_string_lossy().into_owned(),
                    err.to_string(),
                )
            })?;
            let mut store = Vec::<u8>::new();
            (&*guard).read_to_end(&mut store).map_err(|err| {
                LoadStoreError::ReadWallet(
                    self.store_dir().to_str().unwrap().parse().unwrap(),
                    err.to_string(),
                )
            })?;
            wallet.store =
                Store::decode(store).map_err(LoadStoreError::Decode)?;
            Ok(())
        }

        fn load_in_mem<U>(
            &self,
            wallet: &mut Wallet<U>,
        ) -> Result<(), LoadStoreError> {
            wallet.store_in_mem = Some(self.load_store_read_only()?);
            Ok(())
        }

        fn load_store_read_only(&self) -> Result<Store, LoadStoreError> {
            let wallet_file = self.store_dir().join(FILE_NAME);
            let mut options = fs::OpenOptions::new();
            options.read(true).write(false);
            let lock =
                RwLock::new(options.open(wallet_file).map_err(|err| {
                    LoadStoreError::ReadWallet(
                        self.store_dir().to_str().unwrap().parse().unwrap(),
                        err.to_string(),
                    )
                })?);
            let guard = lock.read().map_err(|err| {
                LoadStoreError::ReadWallet(
                    self.store_dir().to_str().unwrap().parse().unwrap(),
                    err.to_string(),
                )
            })?;
            let mut store = Vec::<u8>::new();
            (&*guard).read_to_end(&mut store).map_err(|err| {
                LoadStoreError::ReadWallet(
                    self.store_dir().to_str().unwrap().parse().unwrap(),
                    err.to_string(),
                )
            })?;
            Store::decode(store).map_err(LoadStoreError::Decode)
        }

        fn update_store(
            &self,
            update: impl FnOnce(&mut Store),
        ) -> Result<(), LoadStoreError> {
            let wallet_file = self.store_dir().join(FILE_NAME);
            let mut options = fs::OpenOptions::new();
            options.create(true).write(true).truncate(true);
            let mut lock =
                RwLock::new(options.open(wallet_file).map_err(|err| {
                    LoadStoreError::UpdateWallet(
                        self.store_dir().to_str().unwrap().parse().unwrap(),
                        err.to_string(),
                    )
                })?);
            let mut guard = lock.write().map_err(|err| {
                LoadStoreError::UpdateWallet(
                    self.store_dir().to_str().unwrap().parse().unwrap(),
                    err.to_string(),
                )
            })?;
            let mut store = Vec::<u8>::new();
            (&*guard).read_to_end(&mut store).map_err(|err| {
                LoadStoreError::UpdateWallet(
                    self.store_dir().to_str().unwrap().parse().unwrap(),
                    err.to_string(),
                )
            })?;
            let mut store =
                Store::decode(store).map_err(LoadStoreError::Decode)?;

            // Apply store transformation
            update(&mut store);

            let data = store.encode();
            // XXX
            // Make sure the dir exists
            // let wallet_dir = wallet_path.parent().unwrap();
            // fs::create_dir_all(wallet_dir).map_err(|err| {
            //     LoadStoreError::StoreNewWallet(err.to_string())
            // })?;
            // Write the file
            guard
                .write_all(&data)
                .map_err(|err| LoadStoreError::StoreNewWallet(err.to_string()))
        }
        // fn close<U>(&self, wallet: &Wallet<U>, storage_lock:
        // WalletStorageLock) -> Result<(), LoadStoreError> {
        //     Ok(())
        // }
    }

    /// For a non-interactive filesystem based wallet
    #[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
    pub struct FsWalletUtils {
        #[borsh(skip)]
        store_dir: PathBuf,
    }

    impl FsWalletUtils {
        /// Initialize a wallet at the given directory
        // pub fn new(store_dir: PathBuf) -> Wallet<Self> {
        //     Wallet::new(Self { store_dir })
        // }

        pub fn new(store_dir: PathBuf) -> Wallet<Self> {
            Wallet::new(Self { store_dir }, Store::default())
        }
    }

    impl WalletIo for FsWalletUtils {
        type Rng = OsRng;
    }

    impl FsWalletStorage for FsWalletUtils {
        fn store_dir(&self) -> &PathBuf {
            &self.store_dir
        }
    }
}

/// Generate a new secret key.
pub fn gen_secret_key(
    scheme: SchemeType,
    csprng: &mut (impl CryptoRng + RngCore),
) -> common::SecretKey {
    match scheme {
        SchemeType::Ed25519 => ed25519::SigScheme::generate(csprng).try_to_sk(),
        SchemeType::Secp256k1 => {
            secp256k1::SigScheme::generate(csprng).try_to_sk()
        }
        SchemeType::Common => common::SigScheme::generate(csprng).try_to_sk(),
    }
    .unwrap()
}

fn gen_spending_key(
    csprng: &mut (impl CryptoRng + RngCore),
) -> ExtendedSpendingKey {
    let mut spend_key = [0; 32];
    csprng.fill_bytes(&mut spend_key);
    masp_primitives::zip32::ExtendedSpendingKey::master(spend_key.as_ref())
        .into()
}

/// The error that is produced when a given key cannot be obtained
#[derive(Error, Debug)]
pub enum FindKeyError {
    /// Could not find a given key in the wallet
    #[error("No key matching {0} found")]
    KeyNotFound(String),
    /// Could not decrypt a given key in the wallet
    #[error("{0}")]
    KeyDecryptionError(keys::DecryptionError),
}

/// Represents a collection of keys and addresses while caching key decryptions
#[derive(Debug)]
pub struct Wallet<U> {
    /// Location where this shielded context is saved
    utils: U,
    store: Store,
    store_in_mem: Option<Store>,
    decrypted_key_cache: HashMap<Alias, common::SecretKey>,
    decrypted_spendkey_cache: HashMap<Alias, ExtendedSpendingKey>,
}

impl<U> From<Wallet<U>> for Store {
    fn from(wallet: Wallet<U>) -> Self {
        wallet.store
    }
}

impl<U> Wallet<U> {
    /// Create a new wallet from the given backing store and storage location
    // pub fn new(utils: U) -> Self {
    pub fn new(utils: U, store: Store) -> Self {
        Self {
            utils,
            store,
            // XXX comment
            store_in_mem: Option::default(),
            decrypted_key_cache: HashMap::default(),
            decrypted_spendkey_cache: HashMap::default(),
        }
    }

    // pub fn new(utils: U, store_location: Path) -> Self {
    //     Self {
    //         utils,
    //         store: Store::default(),
    //         store_location,
    //         decrypted_key_cache: HashMap::default(),
    //         decrypted_spendkey_cache: HashMap::default(),
    //     }
    // }

    // XXX REMOVE?
    /// Returns a mut reference to the validator data, if it exists.
    // pub fn get_validator_data_mut(&mut self) -> Option<&mut ValidatorData> {
    //     self.store.get_validator_data_mut()
    // }

    /// Returns the validator data, if it exists.
    pub fn into_validator_data(self) -> Option<ValidatorData> {
        self.store.into_validator_data()
    }

    // XXX REMOVE?
    /// Provide immutable access to the backing store
    pub fn store(&self) -> &Store {
        &self.store
    }

    // XXX REMOVE?
    /// Provide mutable access to the backing store
    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }
}

// XXX HERE
impl<U: WalletStorage> Wallet<U> {
    /// Load a wallet from the store file.
    pub fn load(&mut self) -> Result<(), LoadStoreError> {
        self.utils.clone().load(self)
    }

    /// Save the wallet store to a file.
    pub fn save(&self) -> Result<(), LoadStoreError> {
        self.utils.save(self)
    }

    pub fn set_dry_run(&mut self) -> Result<(), LoadStoreError> {
        self.utils.clone().load_in_mem(self)
    }

    fn into_store(self) -> Result<Store, LoadStoreError> {
        if let Some(store) = self.store_in_mem {
            // return in-memory wallet store
            Ok(store)
        } else {
            // read wallet storage
            self.utils.load_store_read_only()
        }
    }

    fn get_store(&self) -> Result<Store, LoadStoreError> {
        if let Some(ref store) = self.store_in_mem {
            // return in-memory wallet store
            Ok(store.clone())
        } else {
            // read wallet storage
            self.utils.load_store_read_only()
        }
    }

    fn update_store(
        &mut self,
        update: impl FnOnce(&mut Store),
    ) -> Result<(), LoadStoreError> {
        if let Some(store) = &mut self.store_in_mem {
            // update in-memory wallet store (e.g., for dry-run tx
            // executions)
            update(store);
            Ok(())
        } else {
            // update wallet storage
            self.utils.update_store(update)
        }
    }

    /// Add validator data to the store
    pub fn add_validator_data_atomic(
        &mut self,
        address: Address,
        keys: ValidatorKeys,
    ) -> Result<(), LoadStoreError> {
        self.update_store(|store| store.add_validator_data(address, keys))
    }

    /// Returns the validator data, if it exists.
    pub fn get_validator_data_atomic(&self) -> Option<ValidatorData> {
        self.get_store().ok().and_then(Store::into_validator_data)
    }

    /// Returns the validator data, if it exists.
    pub fn into_validator_data_atomic(self) -> Option<ValidatorData> {
        self.into_store().ok().and_then(Store::into_validator_data)
    }

    /// Extend the wallet from pre-genesis validator wallet.
    pub fn extend_from_pre_genesis_validator_atomic(
        &mut self,
        validator_address: Address,
        validator_alias: Alias,
        other: pre_genesis::ValidatorWallet,
    ) -> Result<(), LoadStoreError> {
        self.update_store(|store| {
            store.extend_from_pre_genesis_validator(
                validator_address,
                validator_alias,
                other,
            )
        })
    }

    /// Gets all addresses given a vp_type
    pub fn get_addresses_with_vp_type_atomic(
        &self,
        vp_type: AddressVpType,
    ) -> Result<HashSet<Address>, LoadStoreError> {
        Ok(self.get_store()?.get_addresses_with_vp_type(vp_type))
    }

    /// Add a vp_type to a given address
    pub fn add_vp_type_to_address_atomic(
        &mut self,
        vp_type: AddressVpType,
        address: Address,
    ) -> Result<(), LoadStoreError> {
        self.update_store(|store| {
            store.add_vp_type_to_address(vp_type, address)
        })
    }

    /// Get addresses with tokens VP type keyed and ordered by their aliases.
    pub fn tokens_with_aliases_atomic(
        &self,
    ) -> Result<BTreeMap<String, Address>, LoadStoreError> {
        let res = self
            .get_addresses_with_vp_type_atomic(AddressVpType::Token)?
            .into_iter()
            .map(|addr| match self.lookup_alias_atomic(&addr) {
                Ok(alias) => Ok((alias, addr)),
                Err(err) => Err(err),
            })
            .collect::<Vec<_>>();
        // TODO rewrite when Iter::try_collect gets stabilized
        if let Some(Err(err)) = res.iter().find(|x| x.is_err()) {
            Err(err.clone())
        } else {
            Ok(res.into_iter().map(Result::unwrap).collect())
        }
    }

    /// Find the stored address by an alias.
    pub fn find_address_atomic(
        &self,
        alias: impl AsRef<str>,
    ) -> Result<Option<Address>, LoadStoreError> {
        Alias::is_reserved(alias.as_ref())
            .map(Ok)
            .or_else(|| {
                self.get_store()
                    .map(move |store| store.find_address(alias).cloned())
                    .transpose()
            })
            .transpose()
    }

    /// Find an alias by the address if it's in the wallet.
    pub fn find_alias_atomic(
        &self,
        address: &Address,
    ) -> Result<Option<Alias>, LoadStoreError> {
        Ok(self.get_store()?.find_alias(address).cloned())
    }

    /// Try to find an alias for a given address from the wallet. If not found,
    /// formats the address into a string.
    pub fn lookup_alias_atomic(
        &self,
        addr: &Address,
    ) -> Result<String, LoadStoreError> {
        Ok(match self.find_alias_atomic(addr)? {
            Some(alias) => format!("{}", alias),
            None => format!("{}", addr),
        })
    }

    /// Try to find an alias of the base token in the given IBC denomination
    /// from the wallet. If not found, formats the IBC denomination into a
    /// string.
    pub fn lookup_ibc_token_alias_atomic(
        &self,
        ibc_denom: impl AsRef<str>,
    ) -> Result<String, LoadStoreError> {
        // Convert only an IBC denom or a Namada address since an NFT trace
        // doesn't have the alias
        is_ibc_denom(&ibc_denom)
            .map(|(trace_path, base_token)| {
                let base_token_alias = match Address::decode(&base_token) {
                    Ok(base_token) => self.lookup_alias_atomic(&base_token)?,
                    Err(_) => base_token,
                };
                let alias = if trace_path.is_empty() {
                    base_token_alias
                } else {
                    format!("{}/{}", trace_path, base_token_alias)
                };
                Ok(alias)
            })
            .or_else(|| {
                // It's not an IBC denom, but could be a raw Namada address
                match Address::decode(&ibc_denom) {
                    Ok(addr) => Some(self.lookup_alias_atomic(&addr)),
                    Err(_) => None,
                }
            })
            .unwrap_or(Ok(ibc_denom.as_ref().to_string()))
    }

    /// Find the viewing key with the given alias in the wallet and return it
    pub fn find_viewing_key_atomic(
        &self,
        alias: impl AsRef<str>,
    ) -> Result<Result<ExtendedViewingKey, FindKeyError>, LoadStoreError> {
        Ok(self
            .get_store()?
            .find_viewing_key(alias.as_ref())
            .cloned()
            .ok_or_else(|| {
                FindKeyError::KeyNotFound(alias.as_ref().to_string())
            }))
    }

    /// Find the payment address with the given alias in the wallet and return
    /// it
    pub fn find_payment_addr_atomic(
        &self,
        alias: impl AsRef<str>,
    ) -> Result<Option<PaymentAddress>, LoadStoreError> {
        Ok(self.get_store()?.find_payment_addr(alias.as_ref()).cloned())
    }

    /// Find an alias by the payment address if it's in the wallet.
    pub fn find_alias_by_payment_addr_atomic(
        &self,
        payment_address: &PaymentAddress,
    ) -> Result<Option<Alias>, LoadStoreError> {
        Ok(self
            .get_store()?
            .find_alias_by_payment_addr(payment_address)
            .cloned())
    }

    /// Get all known keys by their alias, paired with PKH, if known.
    #[allow(clippy::type_complexity)]
    pub fn get_secret_keys_atomic(
        &self,
    ) -> Result<
        HashMap<
            String,
            (StoredKeypair<common::SecretKey>, Option<PublicKeyHash>),
        >,
        LoadStoreError,
    > {
        Ok(self
            .get_store()?
            .get_secret_keys()
            .into_iter()
            .map(|(alias, (kp, pkh))| {
                (alias.into(), (kp.clone(), pkh.cloned()))
            })
            .collect())
    }

    /// Get all known public keys by their alias.
    pub fn get_public_keys_atomic(
        &self,
    ) -> Result<HashMap<String, common::PublicKey>, LoadStoreError> {
        Ok(self
            .get_store()?
            .get_public_keys()
            .iter()
            .map(|(alias, value)| (alias.into(), value.clone()))
            .collect())
    }

    /// Get all known addresses by their alias, paired with PKH, if known.
    pub fn get_addresses_atomic(
        &self,
    ) -> Result<HashMap<String, Address>, LoadStoreError> {
        Ok(self
            .get_store()?
            .get_addresses()
            .iter()
            .map(|(alias, value)| (alias.into(), value.clone()))
            .collect())
    }

    /// Get all known payment addresses by their alias
    pub fn get_payment_addrs_atomic(
        &self,
    ) -> Result<HashMap<String, PaymentAddress>, LoadStoreError> {
        Ok(self
            .get_store()?
            .get_payment_addrs()
            .iter()
            .map(|(alias, value)| (alias.into(), *value))
            .collect())
    }

    /// Get all known viewing keys by their alias
    pub fn get_viewing_keys_atomic(
        &self,
    ) -> Result<HashMap<String, ExtendedViewingKey>, LoadStoreError> {
        Ok(self
            .get_store()?
            .get_viewing_keys()
            .iter()
            .map(|(alias, value)| (alias.into(), *value))
            .collect())
    }

    /// Get all known viewing keys by their alias
    pub fn get_spending_keys_atomic(
        &self,
    ) -> Result<
        HashMap<String, StoredKeypair<ExtendedSpendingKey>>,
        LoadStoreError,
    > {
        Ok(self
            .get_store()?
            .get_spending_keys()
            .iter()
            .map(|(alias, value)| (alias.into(), value.clone()))
            .collect())
    }

    /// Check if alias is an encrypted secret key
    pub fn is_encrypted_secret_key_atomic(
        &self,
        alias: impl AsRef<str>,
    ) -> Result<Option<bool>, LoadStoreError> {
        Ok(self
            .get_store()?
            .find_secret_key(alias)
            .map(|stored_keypair| stored_keypair.is_encrypted()))
    }

    /// Check if alias is an encrypted spending key
    pub fn is_encrypted_spending_key_atomic(
        &self,
        alias: impl AsRef<str>,
    ) -> Result<Option<bool>, LoadStoreError> {
        Ok(self
            .utils
            .load_store_read_only()?
            .find_spending_key(alias)
            .map(|stored_spend_key| stored_spend_key.is_encrypted()))
    }

    /// Find a derivation path by public key hash
    pub fn find_path_by_pkh_atomic(
        &self,
        pkh: &PublicKeyHash,
    ) -> Result<Result<DerivationPath, FindKeyError>, LoadStoreError> {
        Ok(self
            .get_store()?
            .find_path_by_pkh(pkh)
            .ok_or_else(|| FindKeyError::KeyNotFound(pkh.to_string())))
    }

    /// Find the public key by a public key hash.
    /// If the key is encrypted and password not supplied, then password will be
    /// interactively prompted for. Any keys that are decrypted are stored in
    /// and read from a cache to avoid prompting for password multiple times.
    pub fn find_public_key_by_pkh_atomic(
        &self,
        pkh: &PublicKeyHash,
    ) -> Result<Result<common::PublicKey, FindKeyError>, LoadStoreError> {
        Ok(self
            .get_store()?
            .find_public_key_by_pkh(pkh)
            .cloned()
            .ok_or_else(|| FindKeyError::KeyNotFound(pkh.to_string())))
    }

    /// Find the public key by an alias or a public key hash.
    pub fn find_public_key_atomic(
        &self,
        alias_or_pkh: impl AsRef<str>,
    ) -> Result<Result<common::PublicKey, FindKeyError>, LoadStoreError> {
        Ok(self
            .get_store()?
            .find_public_key(alias_or_pkh.as_ref())
            .cloned()
            .ok_or_else(|| {
                FindKeyError::KeyNotFound(alias_or_pkh.as_ref().to_string())
            }))
    }

    /// Extend this wallet from another wallet (typically pre-genesis).
    /// Note that this method ignores `store.validator_data` if any.
    pub fn extend_atomic(
        &mut self,
        wallet: Self,
    ) -> Result<(), LoadStoreError> {
        let other_store = wallet.into_store()?;
        self.update_store(|store| store.extend(other_store))
    }

    /// Remove keys and addresses associated with the given alias
    pub fn remove_all_by_alias_atomic(
        &mut self,
        alias: String,
    ) -> Result<(), LoadStoreError> {
        self.update_store(|store| store.remove_alias(&alias.into()))
    }
}

impl<U: WalletIo> Wallet<U> {
    // XXX OK
    /// Generate a BIP39 mnemonic code, and derive HD wallet seed from it using
    /// the given passphrase. If no passphrase is provided, optionally prompt
    /// for a passphrase.
    pub fn gen_hd_seed(
        passphrase: Option<Zeroizing<String>>,
        rng: &mut U::Rng,
        prompt_bip39_passphrase: bool,
    ) -> (Mnemonic, Seed) {
        const MNEMONIC_TYPE: MnemonicType = MnemonicType::Words24;
        let mnemonic = U::generate_mnemonic_code(MNEMONIC_TYPE, rng);
        println!(
            "Safely store your {} words mnemonic.",
            MNEMONIC_TYPE.word_count()
        );
        println!("{}", mnemonic.clone().into_phrase());

        let passphrase = passphrase.unwrap_or_else(|| {
            if prompt_bip39_passphrase {
                U::read_mnemonic_passphrase(true)
            } else {
                Zeroizing::default()
            }
        });
        let seed = Seed::new(&mnemonic, &passphrase);
        (mnemonic, seed)
    }

    /// XXX OK
    /// Derive HD wallet seed from the BIP39 mnemonic code and passphrase. If no
    /// passphrase is provided, optionally prompt for a passphrase.
    pub fn derive_hd_seed(
        mnemonic_passphrase: Option<(Mnemonic, Zeroizing<String>)>,
        prompt_bip39_passphrase: bool,
    ) -> Option<Seed> {
        let (mnemonic, passphrase) = mnemonic_passphrase.or_else(|| {
            let mnemonic = U::read_mnemonic_code()?;
            let passphrase = if prompt_bip39_passphrase {
                U::read_mnemonic_passphrase(false)
            } else {
                Zeroizing::default()
            };
            Some((mnemonic, passphrase))
        })?;
        Some(Seed::new(&mnemonic, &passphrase))
    }

    /// XXX OK
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
        password: Option<Zeroizing<String>>,
    ) -> Result<T, FindKeyError>
    where
        <T as std::str::FromStr>::Err: Display,
    {
        match stored_key {
            StoredKeypair::Encrypted(encrypted) => {
                let password =
                    password.unwrap_or_else(|| U::read_password(false));
                let key = encrypted
                    .decrypt(password)
                    .map_err(FindKeyError::KeyDecryptionError)?;
                decrypted_key_cache.insert(alias.clone(), key);
                decrypted_key_cache
                    .get(&alias)
                    .cloned()
                    .ok_or_else(|| FindKeyError::KeyNotFound(alias.to_string()))
            }
            StoredKeypair::Raw(raw) => Ok(raw.clone()),
        }
    }
}

impl<U: WalletIo + WalletStorage> Wallet<U> {
    /// Find the stored key by a public key.
    /// If the key is encrypted and password not supplied, then password will be
    /// interactively prompted for. Any keys that are decrypted are stored in
    /// and read from a cache to avoid prompting for password multiple times.
    pub fn find_key_by_pk_atomic(
        &mut self,
        pk: &common::PublicKey,
        password: Option<Zeroizing<String>>,
    ) -> Result<Result<common::SecretKey, FindKeyError>, LoadStoreError> {
        // Try to look-up alias for the given pk. Otherwise, use the PKH string.
        let pkh: PublicKeyHash = pk.into();
        self.find_key_by_pkh_atomic(&pkh, password)
    }

    /// Find the stored key by a public key hash.
    /// If the key is encrypted and password is not supplied, then password will
    /// be interactively prompted for. Any keys that are decrypted are stored in
    /// and read from a cache to avoid prompting for password multiple times.
    pub fn find_key_by_pkh_atomic(
        &mut self,
        pkh: &PublicKeyHash,
        password: Option<Zeroizing<String>>,
    ) -> Result<Result<common::SecretKey, FindKeyError>, LoadStoreError> {
        let store = self.get_store()?;
        // Try to look-up alias for the given pk. Otherwise, use the PKH string.
        let alias = store
            .find_alias_by_pkh(pkh)
            .unwrap_or_else(|| pkh.to_string().into());
        // Try read cache
        if let Some(cached_key) = self.decrypted_key_cache.get(&alias) {
            return Ok(Ok(cached_key.clone()));
        }
        // Look-up from store
        let res = if let Some(stored_key) = store.find_key_by_pkh(pkh) {
            Self::decrypt_stored_key(
                &mut self.decrypted_key_cache,
                stored_key,
                alias,
                password,
            )
        } else {
            Err(FindKeyError::KeyNotFound(pkh.to_string()))
        };
        Ok(res)
    }

    /// Find the stored key by an alias, a public key hash or a public key.
    /// If the key is encrypted and password not supplied, then password will be
    /// interactively prompted. Any keys that are decrypted are stored in and
    /// read from a cache to avoid prompting for password multiple times.
    pub fn find_secret_key_atomic(
        &mut self,
        alias_pkh_or_pk: impl AsRef<str>,
        password: Option<Zeroizing<String>>,
    ) -> Result<Result<common::SecretKey, FindKeyError>, LoadStoreError> {
        // Try cache first
        if let Some(cached_key) = self
            .decrypted_key_cache
            .get(&Alias::from(alias_pkh_or_pk.as_ref()))
        {
            return Ok(Ok(cached_key.clone()));
        }
        // If not cached, look-up in store
        let res = if let Some(stored_key) =
            self.get_store()?.find_secret_key(alias_pkh_or_pk.as_ref())
        {
            Self::decrypt_stored_key::<_>(
                &mut self.decrypted_key_cache,
                stored_key,
                alias_pkh_or_pk.into(),
                password,
            )
        } else {
            Err(FindKeyError::KeyNotFound(
                alias_pkh_or_pk.as_ref().to_string(),
            ))
        };
        Ok(res)
    }

    /// Find the spending key with the given alias in the wallet and return it.
    /// If the spending key is encrypted but a password is not supplied, then it
    /// will be interactively prompted.
    pub fn find_spending_key_atomic(
        &mut self,
        alias: impl AsRef<str>,
        password: Option<Zeroizing<String>>,
    ) -> Result<Result<ExtendedSpendingKey, FindKeyError>, LoadStoreError> {
        // Try cache first
        if let Some(cached_key) = self
            .decrypted_spendkey_cache
            .get(&Alias::from(alias.as_ref()))
        {
            return Ok(Ok(*cached_key));
        }
        // If not cached, look-up in store
        let res = if let Some(stored_spendkey) =
            self.get_store()?.find_spending_key(alias.as_ref())
        {
            Self::decrypt_stored_key::<_>(
                &mut self.decrypted_spendkey_cache,
                stored_spendkey,
                alias.into(),
                password,
            )
        } else {
            Err(FindKeyError::KeyNotFound(alias.as_ref().to_string()))
        };
        Ok(res)
    }

    /// Add a new address with the given alias. If the alias is already used,
    /// will ask whether the existing alias should be replaced, a different
    /// alias is desired, or the alias creation should be cancelled. Return
    /// the chosen alias if the address has been added, otherwise return
    /// nothing.
    pub fn insert_address_atomic(
        &mut self,
        alias: impl AsRef<str>,
        address: Address,
        force_alias: bool,
    ) -> Result<Option<String>, LoadStoreError> {
        let mut addr_alias: Option<Alias> = Option::default();
        self.utils.update_store(|store| {
            addr_alias =
                store.insert_address::<U>(alias.into(), address, force_alias);
        })?;
        Ok(addr_alias.map(Into::into))
    }

    /// Add a new keypair with the given alias. If the alias is already used,
    /// will ask whether the existing alias should be replaced, a different
    /// alias is desired, or the alias creation should be cancelled. Return
    /// the chosen alias if the keypair has been added, otherwise return
    /// nothing.
    pub fn insert_keypair_atomic(
        &mut self,
        alias: String,
        force_alias: bool,
        sk: common::SecretKey,
        password: Option<Zeroizing<String>>,
        address: Option<Address>,
        path: Option<DerivationPath>,
    ) -> Result<Option<String>, LoadStoreError> {
        let mut keypair_alias: Option<Alias> = Option::default();
        self.utils.update_store(|store| {
            keypair_alias = store.insert_keypair::<U>(
                alias.into(),
                sk.clone(),
                password,
                address,
                path,
                force_alias,
            )
        })?;
        Ok(keypair_alias.map(|alias| {
            // Cache the newly added key
            self.decrypted_key_cache.insert(alias.clone(), sk);
            alias.into()
        }))
    }

    /// Insert a new public key with the given alias. If the alias is already
    /// used, then display a prompt for overwrite confirmation.
    pub fn insert_public_key_atomic(
        &mut self,
        alias: String,
        pubkey: common::PublicKey,
        address: Option<Address>,
        path: Option<DerivationPath>,
        force_alias: bool,
    ) -> Result<Option<String>, LoadStoreError> {
        let mut pk_alias: Option<Alias> = Option::default();
        self.utils.update_store(|store| {
            pk_alias = store.insert_public_key::<U>(
                alias.into(),
                pubkey,
                address,
                path,
                force_alias,
            )
        })?;
        Ok(pk_alias.map(Into::into))
    }

    /// Insert a viewing key into the wallet under the given alias
    pub fn insert_viewing_key_atomic(
        &mut self,
        alias: String,
        view_key: ExtendedViewingKey,
        force_alias: bool,
    ) -> Result<Option<String>, LoadStoreError> {
        let mut vk_alias: Option<Alias> = Option::default();
        self.utils.update_store(|store| {
            vk_alias = store.insert_viewing_key::<U>(
                alias.into(),
                view_key,
                force_alias,
            )
        })?;
        Ok(vk_alias.map(Into::into))
    }

    /// Insert a spending key into the wallet under the given alias
    pub fn insert_spending_key_atomic(
        &mut self,
        alias: String,
        force_alias: bool,
        spend_key: ExtendedSpendingKey,
        password: Option<Zeroizing<String>>,
        path: Option<DerivationPath>,
    ) -> Result<Option<String>, LoadStoreError> {
        let mut spend_key_alias: Option<Alias> = Option::default();
        self.utils.update_store(|store| {
            spend_key_alias = store.insert_spending_key::<U>(
                alias.into(),
                spend_key,
                password,
                path,
                force_alias,
            )
        })?;
        Ok(spend_key_alias
            .map(|alias| {
                // Cache the newly added key
                self.decrypted_spendkey_cache
                    .insert(alias.clone(), spend_key);
                alias
            })
            .map(Into::into))
    }

    /// Insert a payment address into the wallet under the given alias
    pub fn insert_payment_addr_atomic(
        &mut self,
        alias: String,
        payment_addr: PaymentAddress,
        force_alias: bool,
    ) -> Result<Option<String>, LoadStoreError> {
        let mut pay_addr_alias: Option<Alias> = Option::default();
        self.utils.update_store(|store| {
            pay_addr_alias = store.insert_payment_addr::<U>(
                alias.into(),
                payment_addr,
                force_alias,
            )
        })?;
        Ok(pay_addr_alias.map(Into::into))
    }

    /// Derive a keypair from the given seed and path, derive an implicit
    /// address from this keypair, and insert them into the store with the
    /// provided alias, converted to lower case. If the alias already
    /// exists, optionally force overwrite the keypair for the alias.
    /// If no encryption password is provided, the keypair will be stored raw
    /// without encryption.
    /// Stores the key in decrypted key cache and returns the alias of the
    /// derived key and the key itself.
    pub fn derive_store_hd_secret_key_atomic(
        &mut self,
        scheme: SchemeType,
        alias: String,
        force_alias: bool,
        seed: Seed,
        derivation_path: DerivationPath,
        password: Option<Zeroizing<String>>,
    ) -> Result<Option<(String, common::SecretKey)>, LoadStoreError> {
        let sk = derive_hd_secret_key(
            scheme,
            seed.as_bytes(),
            derivation_path.clone(),
        );
        let res = self
            .insert_keypair_atomic(
                alias,
                force_alias,
                sk.clone(),
                password,
                None,
                Some(derivation_path),
            )?
            .map(|alias| (alias, sk));
        Ok(res)
    }

    /// Derive a masp shielded key from the given seed and path, and insert it
    /// into the store with the provided alias, converted to lower case. If the
    /// alias already exists, optionally force overwrite the key for the
    /// alias.
    /// If no encryption password is provided, the key will be stored raw
    /// without encryption.
    /// Stores the key in decrypted key cache and returns the alias of the key
    /// and the key itself.
    pub fn derive_store_hd_spendind_key_atomic(
        &mut self,
        alias: String,
        force_alias: bool,
        seed: Seed,
        derivation_path: DerivationPath,
        password: Option<Zeroizing<String>>,
    ) -> Result<Option<(String, ExtendedSpendingKey)>, LoadStoreError> {
        let spend_key =
            derive_hd_spending_key(seed.as_bytes(), derivation_path.clone());
        let res = self
            .insert_spending_key_atomic(
                alias,
                force_alias,
                spend_key,
                password,
                Some(derivation_path),
            )?
            .map(|alias| (alias, spend_key));
        Ok(res)
    }

    // XXX OK
    /// Derive a keypair from the user mnemonic code (read from stdin) using
    /// a given BIP44 derivation path and derive an implicit address from its
    /// public part and insert them into the store with the provided alias,
    /// converted to lower case. If none provided, the alias will be the public
    /// key hash (in lower case too).
    /// The key is encrypted with the provided password. If no password
    /// provided, will prompt for password from stdin.
    /// Stores the key in decrypted key cache and returns the alias of the key
    /// and the derived secret key.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_store_hd_secret_key_from_mnemonic_code(
        &mut self,
        scheme: SchemeType,
        alias: String,
        force_alias: bool,
        derivation_path: DerivationPath,
        mnemonic_passphrase: Option<(Mnemonic, Zeroizing<String>)>,
        prompt_bip39_passphrase: bool,
        password: Option<Zeroizing<String>>,
    ) -> Result<Option<(String, common::SecretKey)>, LoadStoreError> {
        Self::derive_hd_seed(mnemonic_passphrase, prompt_bip39_passphrase)
            .and_then(|seed| {
                self.derive_store_hd_secret_key_atomic(
                    scheme,
                    alias,
                    force_alias,
                    seed,
                    derivation_path,
                    password,
                )
                .transpose()
            })
            .transpose()
    }

    // XXX OK
    /// Derive a spending key from the user mnemonic code (read from stdin)
    /// using a given ZIP32 derivation path and insert it into the store with
    /// the provided alias, converted to lower case.
    /// The key is encrypted with the provided password. If no password
    /// provided, will prompt for password from stdin.
    /// Stores the key in decrypted key cache and returns the alias of the key
    /// and the derived spending key.
    pub fn derive_store_hd_spending_key_from_mnemonic_code(
        &mut self,
        alias: String,
        force_alias: bool,
        derivation_path: DerivationPath,
        mnemonic_passphrase: Option<(Mnemonic, Zeroizing<String>)>,
        prompt_bip39_passphrase: bool,
        password: Option<Zeroizing<String>>,
    ) -> Result<Option<(String, ExtendedSpendingKey)>, LoadStoreError> {
        Self::derive_hd_seed(mnemonic_passphrase, prompt_bip39_passphrase)
            .and_then(|seed| {
                self.derive_store_hd_spendind_key_atomic(
                    alias,
                    force_alias,
                    seed,
                    derivation_path,
                    password,
                )
                .transpose()
            })
            .transpose()
    }

    // XXX OK DONT TOUCH
    /// Generate a new keypair, derive an implicit address from its public key
    /// and insert them into the store with the provided alias, converted to
    /// lower case. If the alias already exists, optionally force overwrite
    /// the keypair for the alias.
    /// If no encryption password is provided, the keypair will be stored raw
    /// without encryption.
    /// Stores the key in decrypted key cache and returns the alias of the key
    /// and the generated keypair.
    pub fn gen_store_secret_key_atomic(
        &mut self,
        scheme: SchemeType,
        alias: Option<String>,
        force_alias: bool,
        password: Option<Zeroizing<String>>,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Option<(String, common::SecretKey)>, LoadStoreError> {
        let sk = gen_secret_key(scheme, rng);
        self.insert_keypair_atomic(
            alias.unwrap_or_default(),
            force_alias,
            sk.clone(),
            password,
            None,
            None,
        )
        .map(|o| o.map(|alias| (alias, sk)))
    }

    // XXX OK DONT TOUCH
    /// Generate a new spending key similarly to how it's done for keypairs
    pub fn gen_store_spending_key_atomic(
        &mut self,
        alias: String,
        password: Option<Zeroizing<String>>,
        force_alias: bool,
        csprng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Option<(String, ExtendedSpendingKey)>, LoadStoreError> {
        let spend_key = gen_spending_key(csprng);
        self.insert_spending_key_atomic(
            alias,
            force_alias,
            spend_key,
            password,
            None,
        )
        .map(|o| o.map(|alias| (alias, spend_key)))
    }

    /// Generate a disposable signing key for fee payment and store it under the
    /// precomputed alias in the wallet. This is simply a wrapper around
    /// `gen_key` to manage the alias
    pub fn gen_disposable_signing_key_atomic(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<common::SecretKey, LoadStoreError> {
        // Create the alias
        let mut ctr = 1;
        let mut alias = format!("disposable_{ctr}");

        while self.store().contains_alias(&Alias::from(&alias)) {
            ctr += 1;
            alias = format!("disposable_{ctr}");
        }
        // Generate a disposable keypair to sign the wrapper if requested
        // TODO: once the wrapper transaction has been applied, this key can be
        // deleted from wallet (the transaction being accepted is not enough
        // cause we could end up doing a rollback)
        let (alias, disposable_keypair) = self
            .gen_store_secret_key_atomic(
                SchemeType::Ed25519,
                Some(alias),
                false,
                None,
                rng,
            )?
            .expect("Failed to initialize disposable keypair");

        println!("Created disposable keypair with alias {alias}");
        Ok(disposable_keypair)
    }
}
