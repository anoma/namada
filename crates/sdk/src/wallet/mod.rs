//! Provides functionality for managing keys and addresses for a user
pub mod alias;
mod derivation_path;
mod keys;
pub mod pre_genesis;
pub mod store;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Display;
use std::str::FromStr;

use alias::Alias;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::address::Address;
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
#[derive(Error, Debug)]
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
}

/// Captures the permanent storage parts of the wallet's functioning
pub trait WalletStorage: Sized + Clone {
    /// Save the wallet store to a file.
    fn save<U>(&self, wallet: &Wallet<U>) -> Result<(), LoadStoreError>;

    /// Load a wallet from the store file.
    fn load<U>(&self, wallet: &mut Wallet<U>) -> Result<(), LoadStoreError>;
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
    }

    /// For a non-interactive filesystem based wallet
    #[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
    pub struct FsWalletUtils {
        #[borsh(skip)]
        store_dir: PathBuf,
    }

    impl FsWalletUtils {
        /// Initialize a wallet at the given directory
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
    pub fn new(utils: U, store: Store) -> Self {
        Self {
            utils,
            store,
            decrypted_key_cache: HashMap::default(),
            decrypted_spendkey_cache: HashMap::default(),
        }
    }

    /// Add validator data to the store
    pub fn add_validator_data(
        &mut self,
        address: Address,
        keys: ValidatorKeys,
    ) {
        self.store.add_validator_data(address, keys);
    }

    /// Returns a reference to the validator data, if it exists.
    pub fn get_validator_data(&self) -> Option<&ValidatorData> {
        self.store.get_validator_data()
    }

    /// Returns a mut reference to the validator data, if it exists.
    pub fn get_validator_data_mut(&mut self) -> Option<&mut ValidatorData> {
        self.store.get_validator_data_mut()
    }

    /// Take the validator data, if it exists.
    pub fn take_validator_data(&mut self) -> Option<ValidatorData> {
        self.store.take_validator_data()
    }

    /// Returns the validator data, if it exists.
    pub fn into_validator_data(self) -> Option<ValidatorData> {
        self.store.into_validator_data()
    }

    /// Provide immutable access to the backing store
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Provide mutable access to the backing store
    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
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

    /// Get addresses with tokens VP type keyed and ordered by their aliases.
    pub fn tokens_with_aliases(&self) -> BTreeMap<String, Address> {
        self.get_addresses_with_vp_type(AddressVpType::Token)
            .into_iter()
            .map(|addr| {
                let alias = self.lookup_alias(&addr);
                (alias, addr)
            })
            .collect()
    }

    /// Find the stored address by an alias.
    pub fn find_address(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<std::borrow::Cow<Address>> {
        Alias::is_reserved(alias.as_ref())
            .map(std::borrow::Cow::Owned)
            .or_else(|| {
                self.store
                    .find_address(alias)
                    .map(std::borrow::Cow::Borrowed)
            })
    }

    /// Find an alias by the address if it's in the wallet.
    pub fn find_alias(&self, address: &Address) -> Option<&Alias> {
        self.store.find_alias(address)
    }

    /// Try to find an alias for a given address from the wallet. If not found,
    /// formats the address into a string.
    pub fn lookup_alias(&self, addr: &Address) -> String {
        match self.find_alias(addr) {
            Some(alias) => format!("{}", alias),
            None => format!("{}", addr),
        }
    }

    /// Find the viewing key with the given alias in the wallet and return it
    pub fn find_viewing_key(
        &self,
        alias: impl AsRef<str>,
    ) -> Result<&ExtendedViewingKey, FindKeyError> {
        self.store.find_viewing_key(alias.as_ref()).ok_or_else(|| {
            FindKeyError::KeyNotFound(alias.as_ref().to_string())
        })
    }

    /// Find the payment address with the given alias in the wallet and return
    /// it
    pub fn find_payment_addr(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<&PaymentAddress> {
        self.store.find_payment_addr(alias.as_ref())
    }

    /// Find an alias by the payment address if it's in the wallet.
    pub fn find_alias_by_payment_addr(
        &self,
        payment_address: &PaymentAddress,
    ) -> Option<&Alias> {
        self.store.find_alias_by_payment_addr(payment_address)
    }

    /// Get all known keys by their alias, paired with PKH, if known.
    pub fn get_secret_keys(
        &self,
    ) -> HashMap<
        String,
        (&StoredKeypair<common::SecretKey>, Option<&PublicKeyHash>),
    > {
        self.store
            .get_secret_keys()
            .into_iter()
            .map(|(alias, value)| (alias.into(), value))
            .collect()
    }

    /// Get all known public keys by their alias.
    pub fn get_public_keys(&self) -> HashMap<String, common::PublicKey> {
        self.store
            .get_public_keys()
            .iter()
            .map(|(alias, value)| (alias.into(), value.clone()))
            .collect()
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

    /// Check if alias is an encrypted secret key
    pub fn is_encrypted_secret_key(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<bool> {
        self.store
            .find_secret_key(alias)
            .map(|stored_keypair| stored_keypair.is_encrypted())
    }

    /// Check if alias is an encrypted spending key
    pub fn is_encrypted_spending_key(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<bool> {
        self.store
            .find_spending_key(alias)
            .map(|stored_spend_key| stored_spend_key.is_encrypted())
    }
}

impl<U: WalletStorage> Wallet<U> {
    /// Load a wallet from the store file.
    pub fn load(&mut self) -> Result<(), LoadStoreError> {
        self.utils.clone().load(self)
    }

    /// Save the wallet store to a file.
    pub fn save(&self) -> Result<(), LoadStoreError> {
        self.utils.save(self)
    }
}

impl<U: WalletIo> Wallet<U> {
    /// Restore a spending key from the user mnemonic code (read from stdin)
    /// using a given ZIP32 derivation path and insert it into the store with
    /// the provided alias, converted to lower case.
    /// The key is encrypted with the provided password. If no password
    /// provided, will prompt for password from stdin.
    /// Stores the key in decrypted key cache and returns the alias of the key
    /// and a reference-counting pointer to the key.
    pub fn derive_store_spending_key_from_mnemonic_code(
        &mut self,
        alias: String,
        alias_force: bool,
        derivation_path: DerivationPath,
        mnemonic_passphrase: Option<(Mnemonic, Zeroizing<String>)>,
        prompt_bip39_passphrase: bool,
        password: Option<Zeroizing<String>>,
    ) -> Option<(String, ExtendedSpendingKey)> {
        let (mnemonic, passphrase) =
            if let Some(mnemonic_passphrase) = mnemonic_passphrase {
                mnemonic_passphrase
            } else {
                let mnemonic = U::read_mnemonic_code()?;
                let passphrase = if prompt_bip39_passphrase {
                    U::read_mnemonic_passphrase(false)
                } else {
                    Zeroizing::default()
                };
                (mnemonic, passphrase)
            };
        let seed = Seed::new(&mnemonic, &passphrase);
        let spend_key =
            derive_hd_spending_key(seed.as_bytes(), derivation_path.clone());

        self.insert_spending_key(
            alias,
            alias_force,
            spend_key,
            password,
            Some(derivation_path),
        )
        .map(|alias| (alias, spend_key))
    }

    /// Restore a keypair from the user mnemonic code (read from stdin) using
    /// a given BIP44 derivation path and derive an implicit address from its
    /// public part and insert them into the store with the provided alias,
    /// converted to lower case. If none provided, the alias will be the public
    /// key hash (in lowercase too).
    /// The key is encrypted with the provided password. If no password
    /// provided, will prompt for password from stdin.
    /// Stores the key in decrypted key cache and returns the alias of the key
    /// and a reference-counting pointer to the key.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_store_key_from_mnemonic_code(
        &mut self,
        scheme: SchemeType,
        alias: Option<String>,
        alias_force: bool,
        derivation_path: DerivationPath,
        mnemonic_passphrase: Option<(Mnemonic, Zeroizing<String>)>,
        prompt_bip39_passphrase: bool,
        password: Option<Zeroizing<String>>,
    ) -> Option<(String, common::SecretKey)> {
        let (mnemonic, passphrase) =
            if let Some(mnemonic_passphrase) = mnemonic_passphrase {
                mnemonic_passphrase
            } else {
                let mnemonic = U::read_mnemonic_code()?;
                let passphrase = if prompt_bip39_passphrase {
                    U::read_mnemonic_passphrase(false)
                } else {
                    Zeroizing::default()
                };
                (mnemonic, passphrase)
            };
        let seed = Seed::new(&mnemonic, &passphrase);
        let sk = derive_hd_secret_key(
            scheme,
            seed.as_bytes(),
            derivation_path.clone(),
        );

        self.insert_keypair(
            alias.unwrap_or_default(),
            alias_force,
            sk.clone(),
            password,
            None,
            Some(derivation_path),
        )
        .map(|alias| (alias, sk))
    }

    /// Generate a spending key similarly to how it's done for keypairs
    pub fn gen_store_spending_key(
        &mut self,
        alias: String,
        password: Option<Zeroizing<String>>,
        force_alias: bool,
        csprng: &mut (impl CryptoRng + RngCore),
    ) -> Option<(String, ExtendedSpendingKey)> {
        let spend_key = gen_spending_key(csprng);
        self.insert_spending_key(alias, force_alias, spend_key, password, None)
            .map(|alias| (alias, spend_key))
    }

    /// Generate a new keypair, derive an implicit address from its public key
    /// and insert them into the store with the provided alias, converted to
    /// lower case. If none provided, the alias will be the public key hash (in
    /// lowercase too). If the alias already exists, optionally force overwrite
    /// the keypair for the alias.
    /// If no encryption password is provided, the keypair will be stored raw
    /// without encryption.
    /// Stores the key in decrypted key cache and returns the alias of the key
    /// and a reference-counting pointer to the key.
    pub fn gen_store_secret_key(
        &mut self,
        scheme: SchemeType,
        alias: Option<String>,
        alias_force: bool,
        password: Option<Zeroizing<String>>,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Option<(String, common::SecretKey)> {
        let sk = gen_secret_key(scheme, rng);
        self.insert_keypair(
            alias.unwrap_or_default(),
            alias_force,
            sk.clone(),
            password,
            None,
            None,
        )
        .map(|alias| (alias, sk))
    }

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

    /// Derive a keypair from the given seed and path, derive an implicit
    /// address from this keypair, and insert them into the store with the
    /// provided alias, converted to lower case. If none provided, the alias
    /// will be the public key hash (in lowercase too). If the alias already
    /// exists, optionally force overwrite the keypair for the alias.
    /// If no encryption password is provided, the keypair will be stored raw
    /// without encryption.
    /// Stores the key in decrypted key cache and returns the alias of the key
    /// and the key itself.
    pub fn derive_store_hd_secret_key(
        &mut self,
        scheme: SchemeType,
        alias: Option<String>,
        alias_force: bool,
        seed: Seed,
        derivation_path: DerivationPath,
        password: Option<Zeroizing<String>>,
    ) -> Option<(String, common::SecretKey)> {
        let sk = derive_hd_secret_key(
            scheme,
            seed.as_bytes(),
            derivation_path.clone(),
        );
        self.insert_keypair(
            alias.unwrap_or_default(),
            alias_force,
            sk.clone(),
            password,
            None,
            Some(derivation_path),
        )
        .map(|alias| (alias, sk))
    }

    /// Derive a masp shielded key from the given seed and path, and insert it
    /// into the store with the provided alias, converted to lower case. If the
    /// alias already exists, optionally force overwrite the key for the
    /// alias.
    /// If no encryption password is provided, the key will be stored raw
    /// without encryption.
    /// Stores the key in decrypted key cache and returns the alias of the key
    /// and the key itself.
    pub fn derive_store_hd_spendind_key(
        &mut self,
        alias: String,
        force_alias: bool,
        seed: Seed,
        derivation_path: DerivationPath,
        password: Option<Zeroizing<String>>,
    ) -> Option<(String, ExtendedSpendingKey)> {
        let spend_key =
            derive_hd_spending_key(seed.as_bytes(), derivation_path.clone());
        self.insert_spending_key(
            alias,
            force_alias,
            spend_key,
            password,
            Some(derivation_path),
        )
        .map(|alias| (alias, spend_key))
    }

    /// Generate a disposable signing key for fee payment and store it under the
    /// precomputed alias in the wallet. This is simply a wrapper around
    /// `gen_key` to manage the alias
    pub fn gen_disposable_signing_key(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> common::SecretKey {
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
            .gen_store_secret_key(
                SchemeType::Ed25519,
                Some(alias),
                false,
                None,
                rng,
            )
            .expect("Failed to initialize disposable keypair");

        println!("Created disposable keypair with alias {alias}");
        disposable_keypair
    }

    /// Find the stored key by an alias, a public key hash or a public key.
    /// If the key is encrypted and password not supplied, then password will be
    /// interactively prompted. Any keys that are decrypted are stored in and
    /// read from a cache to avoid prompting for password multiple times.
    pub fn find_secret_key(
        &mut self,
        alias_pkh_or_pk: impl AsRef<str>,
        password: Option<Zeroizing<String>>,
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
            .find_secret_key(alias_pkh_or_pk.as_ref())
            .ok_or_else(|| {
            FindKeyError::KeyNotFound(alias_pkh_or_pk.as_ref().to_string())
        })?;
        Self::decrypt_stored_key::<_>(
            &mut self.decrypted_key_cache,
            stored_key,
            alias_pkh_or_pk.into(),
            password,
        )
    }

    /// Find the public key by an alias or a public key hash.
    pub fn find_public_key(
        &self,
        alias_or_pkh: impl AsRef<str>,
    ) -> Result<common::PublicKey, FindKeyError> {
        self.store
            .find_public_key(alias_or_pkh.as_ref())
            .cloned()
            .ok_or_else(|| {
                FindKeyError::KeyNotFound(alias_or_pkh.as_ref().to_string())
            })
    }

    /// Find the spending key with the given alias in the wallet and return it.
    /// If the spending key is encrypted but a password is not supplied, then it
    /// will be interactively prompted.
    pub fn find_spending_key(
        &mut self,
        alias: impl AsRef<str>,
        password: Option<Zeroizing<String>>,
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
            .ok_or_else(|| {
                FindKeyError::KeyNotFound(alias.as_ref().to_string())
            })?;
        Self::decrypt_stored_key::<_>(
            &mut self.decrypted_spendkey_cache,
            stored_spendkey,
            alias.into(),
            password,
        )
    }

    /// Find the stored key by a public key.
    /// If the key is encrypted and password not supplied, then password will be
    /// interactively prompted for. Any keys that are decrypted are stored in
    /// and read from a cache to avoid prompting for password multiple times.
    pub fn find_key_by_pk(
        &mut self,
        pk: &common::PublicKey,
        password: Option<Zeroizing<String>>,
    ) -> Result<common::SecretKey, FindKeyError> {
        // Try to look-up alias for the given pk. Otherwise, use the PKH string.
        let pkh: PublicKeyHash = pk.into();
        self.find_key_by_pkh(&pkh, password)
    }

    /// Find a derivation path by public key hash
    pub fn find_path_by_pkh(
        &self,
        pkh: &PublicKeyHash,
    ) -> Result<DerivationPath, FindKeyError> {
        self.store
            .find_path_by_pkh(pkh)
            .ok_or_else(|| FindKeyError::KeyNotFound(pkh.to_string()))
    }

    /// Find the public key by a public key hash.
    /// If the key is encrypted and password not supplied, then password will be
    /// interactively prompted for. Any keys that are decrypted are stored in
    /// and read from a cache to avoid prompting for password multiple times.
    pub fn find_public_key_by_pkh(
        &self,
        pkh: &PublicKeyHash,
    ) -> Result<common::PublicKey, FindKeyError> {
        self.store
            .find_public_key_by_pkh(pkh)
            .cloned()
            .ok_or_else(|| FindKeyError::KeyNotFound(pkh.to_string()))
    }

    /// Find the stored key by a public key hash.
    /// If the key is encrypted and password is not supplied, then password will
    /// be interactively prompted for. Any keys that are decrypted are stored in
    /// and read from a cache to avoid prompting for password multiple times.
    pub fn find_key_by_pkh(
        &mut self,
        pkh: &PublicKeyHash,
        password: Option<Zeroizing<String>>,
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
            .ok_or_else(|| FindKeyError::KeyNotFound(pkh.to_string()))?;
        Self::decrypt_stored_key(
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

    /// Add a new address with the given alias. If the alias is already used,
    /// will ask whether the existing alias should be replaced, a different
    /// alias is desired, or the alias creation should be cancelled. Return
    /// the chosen alias if the address has been added, otherwise return
    /// nothing.
    pub fn insert_address(
        &mut self,
        alias: impl AsRef<str>,
        address: Address,
        force_alias: bool,
    ) -> Option<String> {
        self.store
            .insert_address::<U>(alias.into(), address, force_alias)
            .map(Into::into)
    }

    /// Add a new keypair with the given alias. If the alias is already used,
    /// will ask whether the existing alias should be replaced, a different
    /// alias is desired, or the alias creation should be cancelled. Return
    /// the chosen alias if the keypair has been added, otherwise return
    /// nothing.
    pub fn insert_keypair(
        &mut self,
        alias: String,
        alias_force: bool,
        sk: common::SecretKey,
        password: Option<Zeroizing<String>>,
        address: Option<Address>,
        path: Option<DerivationPath>,
    ) -> Option<String> {
        self.store
            .insert_keypair::<U>(
                alias.into(),
                sk.clone(),
                password,
                address,
                path,
                alias_force,
            )
            .map(|alias| {
                // Cache the newly added key
                self.decrypted_key_cache.insert(alias.clone(), sk);
                alias.into()
            })
    }

    /// Insert a new public key with the given alias. If the alias is already
    /// used, then display a prompt for overwrite confirmation.
    pub fn insert_public_key(
        &mut self,
        alias: String,
        pubkey: common::PublicKey,
        address: Option<Address>,
        path: Option<DerivationPath>,
        force_alias: bool,
    ) -> Option<String> {
        self.store
            .insert_public_key::<U>(
                alias.into(),
                pubkey,
                address,
                path,
                force_alias,
            )
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
        force_alias: bool,
        spend_key: ExtendedSpendingKey,
        password: Option<Zeroizing<String>>,
        path: Option<DerivationPath>,
    ) -> Option<String> {
        self.store
            .insert_spending_key::<U>(
                alias.into(),
                spend_key,
                password,
                path,
                force_alias,
            )
            .map(|alias| {
                // Cache the newly added key
                self.decrypted_spendkey_cache
                    .insert(alias.clone(), spend_key);
                alias
            })
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

    /// Extend this wallet from another wallet (typically pre-genesis).
    /// Note that this method ignores `store.validator_data` if any.
    pub fn extend(&mut self, wallet: Self) {
        self.store.extend(wallet.store)
    }

    /// Remove keys and addresses associated with the given alias
    pub fn remove_all_by_alias(&mut self, alias: String) {
        self.store.remove_alias(&alias.into())
    }
}
