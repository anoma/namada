mod alias;
pub mod defaults;
mod derivation_path;
mod keys;
pub mod pre_genesis;
mod store;

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{env, error, fs};

use bip39::{Language, Mnemonic, MnemonicType, Seed};
use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::zip32::ExtendedFullViewingKey;
use namada::types::address::Address;
use namada::types::key::*;
use namada::types::masp::{
    ExtendedSpendingKey, ExtendedViewingKey, PaymentAddress,
};
use secstr::SecStr;
pub use store::wallet_file;
use thiserror::Error;

use self::alias::Alias;
use self::derivation_path::{DerivationPath, DerivationPathError};
pub use self::keys::{DecryptionError, StoredKeypair};
use self::store::Store;
pub use self::store::{AddressVpType, ValidatorData, ValidatorKeys};
use crate::cli;
use crate::config::genesis::genesis_config::GenesisConfig;

#[derive(Debug)]
pub struct Wallet {
    store_dir: PathBuf,
    store: Store,
    decrypted_key_cache: HashMap<Alias, common::SecretKey>,
    decrypted_spendkey_cache: HashMap<Alias, ExtendedSpendingKey>,
}

#[derive(Error, Debug)]
pub enum FindKeyError {
    #[error("No matching key found")]
    KeyNotFound,
    #[error("{0}")]
    KeyDecryptionError(keys::DecryptionError),
}

#[derive(Error, Debug)]
pub enum GenRestoreKeyError {
    #[error("Derivation path parse error")]
    DerivationPathError(DerivationPathError),
    #[error("Mnemonic generation error")]
    MnemonicGenerationError,
    #[error("Mnemonic input error")]
    MnemonicInputError,
}

impl Wallet {
    /// Load a wallet from the store file.
    pub fn load(store_dir: &Path) -> Option<Self> {
        let store = Store::load(store_dir).unwrap_or_else(|err| {
            eprintln!("Unable to load the wallet: {}", err);
            cli::safe_exit(1)
        });
        Some(Self {
            store_dir: store_dir.to_path_buf(),
            store,
            decrypted_key_cache: HashMap::default(),
            decrypted_spendkey_cache: HashMap::default(),
        })
    }

    /// Load a wallet from the store file or create a new wallet without any
    /// keys or addresses.
    pub fn load_or_new(store_dir: &Path) -> Self {
        let store = Store::load_or_new(store_dir).unwrap_or_else(|err| {
            eprintln!("Unable to load the wallet: {}", err);
            cli::safe_exit(1)
        });
        Self {
            store_dir: store_dir.to_path_buf(),
            store,
            decrypted_key_cache: HashMap::default(),
            decrypted_spendkey_cache: HashMap::default(),
        }
    }

    /// Load a wallet from the store file or create a new one with the default
    /// addresses loaded from the genesis file, if not found.
    pub fn load_or_new_from_genesis(
        store_dir: &Path,
        genesis_cfg: GenesisConfig,
    ) -> Self {
        let store = Store::load_or_new_from_genesis(store_dir, genesis_cfg)
            .unwrap_or_else(|err| {
                eprintln!("Unable to load the wallet: {}", err);
                cli::safe_exit(1)
            });
        Self {
            store_dir: store_dir.to_path_buf(),
            store,
            decrypted_key_cache: HashMap::default(),
            decrypted_spendkey_cache: HashMap::default(),
        }
    }

    /// Add addresses from a genesis configuration.
    pub fn add_genesis_addresses(&mut self, genesis: GenesisConfig) {
        self.store.add_genesis_addresses(genesis)
    }

    /// Save the wallet store to a file.
    pub fn save(&self) -> std::io::Result<()> {
        self.store.save(&self.store_dir)
    }

    /// Prompt for pssword and confirm it if parameter is false
    fn new_password_prompt(unsafe_dont_encrypt: bool) -> Option<String> {
        let password = if unsafe_dont_encrypt {
            println!("Warning: The keypair will NOT be encrypted.");
            None
        } else {
            Some(read_encryption_password("Enter your encryption password: "))
        };
        // Bis repetita for confirmation.
        let pwd = if unsafe_dont_encrypt {
            None
        } else {
            Some(read_encryption_password(
                "To confirm, please enter the same encryption password once \
                 more: ",
            ))
        };
        if pwd != password {
            eprintln!("Your two inputs do not match!");
            cli::safe_exit(1)
        }
        password
    }

    fn gen_and_store_key(
        &mut self,
        scheme: SchemeType,
        alias: Option<String>,
        encryption_password: Option<String>,
        seed: Option<Seed>,
        use_empty_derivation_path: bool,
        derivation_path: Option<String>,
    ) -> Result<(String, common::SecretKey), GenRestoreKeyError> {
        let derivation_path = derivation_path
            .map(|p| {
                if p.is_empty() {
                    Ok(DerivationPath::default_for_scheme(scheme))
                } else {
                    DerivationPath::from_path_str(&p)
                        .map_err(GenRestoreKeyError::DerivationPathError)
                }
            })
            .transpose()?;
        let derivation_path = use_empty_derivation_path
            .then(DerivationPath::empty)
            .or(derivation_path)
            .unwrap();
        println!("Using HD derivation path {}", derivation_path);
        let (alias, key) = self.store.gen_key(
            scheme,
            alias,
            encryption_password,
            seed,
            derivation_path,
        );
        // Cache the newly added key
        self.decrypted_key_cache.insert(alias.clone(), key.clone());
        Ok((alias.into(), key))
    }

    /// Restore a keypair from the user mnemonic code (read from stdin) and
    /// derive an implicit address from its public part
    /// and insert them into the store with the provided alias, converted to
    /// lower case. If none provided, the alias will be the public key hash (in
    /// lowercase too). If the key is to be encrypted, will prompt for
    /// password from stdin. Stores the key in decrypted key cache and
    /// returns the alias of the key and a reference-counting pointer to the
    /// key.
    /// TO REMOVE Optionally, use BIP44 derivation path for the key recovery.
    pub fn derive_key_from_user_mnemonic_code(
        &mut self,
        scheme: SchemeType,
        alias: Option<String>,
        unsafe_dont_encrypt: bool,
        use_empty_derivation_path: bool,
        derivation_path: Option<String>,
    ) -> Result<(String, common::SecretKey), GenRestoreKeyError> {
        let password =
            read_and_confirm_encryption_password(unsafe_dont_encrypt);
        let mnemonic = read_mnemonic_code()?;
        let seed = Seed::new(&mnemonic, "");
        self.gen_and_store_key(
            scheme,
            alias,
            password,
            Some(seed),
            use_empty_derivation_path,
            derivation_path,
        )
    }

    /// Generate a new keypair and derive an implicit address from its public
    /// and insert them into the store with the provided alias, converted to
    /// lower case. If none provided, the alias will be the public key hash (in
    /// lowercase too). If the key is to be encrypted, will prompt for
    /// password from stdin. Stores the key in decrypted key cache and
    /// returns the alias of the key and a reference-counting pointer to the
    /// key. Optionally, use a BIP39 mnemonic code.
    /// If mnemonic code is not used, the values of derivation path arguments
    /// are ignored.
    /// Use empty derivation path if `true` is passed into the respective
    /// argument. If none BIP44 derivation path is specified, a scheme
    /// default path is used.
    pub fn gen_key(
        &mut self,
        scheme: SchemeType,
        alias: Option<String>,
        unsafe_dont_encrypt: bool,
        use_mnemonic: bool,
        use_empty_derivation_path: bool,
        derivation_path: Option<String>,
    ) -> Result<(String, common::SecretKey), GenRestoreKeyError> {
        let password =
            read_and_confirm_encryption_password(unsafe_dont_encrypt);
        let mnemonic = generate_mnemonic_code(use_mnemonic)?;
        let passphrase = read_and_confirm_mnemonic_passphrase();
        let seed = mnemonic.map(|m| Seed::new(&m, &passphrase));
        self.gen_and_store_key(
            scheme,
            alias,
            password,
            seed,
            use_empty_derivation_path,
            derivation_path,
        )
    }

    pub fn gen_spending_key(
        &mut self,
        alias: String,
        unsafe_dont_encrypt: bool,
    ) -> (String, ExtendedSpendingKey) {
        let password = Self::new_password_prompt(unsafe_dont_encrypt);
        let (alias, key) = self.store.gen_spending_key(alias, password);
        // Cache the newly added key
        self.decrypted_spendkey_cache.insert(alias.clone(), key);
        (alias.into(), key)
    }

    /// Generate keypair
    /// for signing protocol txs and for the DKG (which will also be stored)
    /// A protocol keypair may be optionally provided, indicating that
    /// we should re-use a keypair already in the wallet
    pub fn gen_validator_keys(
        &mut self,
        protocol_pk: Option<common::PublicKey>,
        scheme: SchemeType,
    ) -> Result<ValidatorKeys, FindKeyError> {
        let protocol_keypair = protocol_pk.map(|pk| {
            self.find_key_by_pkh(&PublicKeyHash::from(&pk))
                .ok()
                .or_else(|| {
                    self.store
                        .validator_data
                        .take()
                        .map(|data| data.keys.protocol_keypair)
                })
                .ok_or(FindKeyError::KeyNotFound)
        });
        match protocol_keypair {
            Some(Err(err)) => Err(err),
            other => Ok(Store::gen_validator_keys(
                other.map(|res| res.unwrap()),
                scheme,
            )),
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

    /// Returns the validator data, if it exists.
    pub fn get_validator_data(&self) -> Option<&ValidatorData> {
        self.store.get_validator_data()
    }

    /// Returns the validator data, if it exists.
    /// [`Wallet::save`] cannot be called after using this
    /// method as it involves a partial move
    pub fn take_validator_data(self) -> Option<ValidatorData> {
        self.store.validator_data()
    }

    /// Find the stored key by an alias, a public key hash or a public key.
    /// If the key is encrypted, will prompt for password from stdin.
    /// Any keys that are decrypted are stored in and read from a cache to avoid
    /// prompting for password multiple times.
    pub fn find_key(
        &mut self,
        alias_pkh_or_pk: impl AsRef<str>,
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
        Self::decrypt_stored_key(
            &mut self.decrypted_key_cache,
            stored_key,
            alias_pkh_or_pk.into(),
        )
    }

    pub fn find_spending_key(
        &mut self,
        alias: impl AsRef<str>,
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
        Self::decrypt_stored_key(
            &mut self.decrypted_spendkey_cache,
            stored_spendkey,
            alias.into(),
        )
    }

    pub fn find_viewing_key(
        &mut self,
        alias: impl AsRef<str>,
    ) -> Result<&ExtendedViewingKey, FindKeyError> {
        self.store
            .find_viewing_key(alias.as_ref())
            .ok_or(FindKeyError::KeyNotFound)
    }

    pub fn find_payment_addr(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<&PaymentAddress> {
        self.store.find_payment_addr(alias.as_ref())
    }

    /// Find the stored key by a public key.
    /// If the key is encrypted, will prompt for password from stdin.
    /// Any keys that are decrypted are stored in and read from a cache to avoid
    /// prompting for password multiple times.
    pub fn find_key_by_pk(
        &mut self,
        pk: &common::PublicKey,
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
        Self::decrypt_stored_key(
            &mut self.decrypted_key_cache,
            stored_key,
            alias,
        )
    }

    /// Find the stored key by a public key hash.
    /// If the key is encrypted, will prompt for password from stdin.
    /// Any keys that are decrypted are stored in and read from a cache to avoid
    /// prompting for password multiple times.
    pub fn find_key_by_pkh(
        &mut self,
        pkh: &PublicKeyHash,
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
        Self::decrypt_stored_key(
            &mut self.decrypted_key_cache,
            stored_key,
            alias,
        )
    }

    /// Decrypt stored key, if it's not stored un-encrypted.
    /// If a given storage key needs to be decrypted, prompt for password from
    /// stdin and if successfully decrypted, store it in a cache.
    fn decrypt_stored_key<
        T: FromStr + Display + BorshSerialize + BorshDeserialize + Clone,
    >(
        decrypted_key_cache: &mut HashMap<Alias, T>,
        stored_key: &StoredKeypair<T>,
        alias: Alias,
    ) -> Result<T, FindKeyError>
    where
        <T as std::str::FromStr>::Err: Display,
    {
        match stored_key {
            StoredKeypair::Encrypted(encrypted) => {
                let password =
                    read_encryption_password("Enter decryption password: ");
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
    ) -> Option<String> {
        self.store
            .insert_address(alias.into(), address)
            .map(Into::into)
    }

    /// Insert a new key with the given alias. If the alias is already used,
    /// will prompt for overwrite confirmation.
    pub fn insert_keypair(
        &mut self,
        alias: String,
        keypair: StoredKeypair<common::SecretKey>,
        pkh: PublicKeyHash,
    ) -> Option<String> {
        self.store
            .insert_keypair(alias.into(), keypair, pkh)
            .map(Into::into)
    }

    pub fn insert_viewing_key(
        &mut self,
        alias: String,
        view_key: ExtendedViewingKey,
    ) -> Option<String> {
        self.store
            .insert_viewing_key(alias.into(), view_key)
            .map(Into::into)
    }

    pub fn insert_spending_key(
        &mut self,
        alias: String,
        spend_key: StoredKeypair<ExtendedSpendingKey>,
        viewkey: ExtendedViewingKey,
    ) -> Option<String> {
        self.store
            .insert_spending_key(alias.into(), spend_key, viewkey)
            .map(Into::into)
    }

    pub fn encrypt_insert_spending_key(
        &mut self,
        alias: String,
        spend_key: ExtendedSpendingKey,
        unsafe_dont_encrypt: bool,
    ) -> Option<String> {
        let password = Self::new_password_prompt(unsafe_dont_encrypt);
        self.store
            .insert_spending_key(
                alias.into(),
                StoredKeypair::new(spend_key, password).0,
                ExtendedFullViewingKey::from(&spend_key.into()).into(),
            )
            .map(Into::into)
    }

    pub fn insert_payment_addr(
        &mut self,
        alias: String,
        payment_addr: PaymentAddress,
    ) -> Option<String> {
        self.store
            .insert_payment_addr(alias.into(), payment_addr)
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
}

/// Generates a random mnemonic of the given mnemonic type.
fn generate_and_print_mnemonic_code(
    mnemonic_type: MnemonicType,
) -> Result<Mnemonic, GenRestoreKeyError> {
    const BITS_PER_BYTE: usize = 8;

    // generate random mnemonic
    let entropy_size = mnemonic_type.entropy_bits() / BITS_PER_BYTE;
    let mut bytes = vec![0u8; entropy_size];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let mnemonic = Mnemonic::from_entropy(&bytes, Language::English)
        .expect("Mnemonic creation should not fail");

    #[cfg(not(test))]
    {
        println!(
            "Safely store your {} words mnemonic.",
            mnemonic_type.word_count()
        );
        println!("{}", mnemonic.clone().into_phrase());
    }

    Ok(mnemonic)
}

fn generate_mnemonic_code(
    use_mnemonic: bool,
) -> Result<Option<Mnemonic>, GenRestoreKeyError> {
    const MNEMONIC_TYPE: MnemonicType = MnemonicType::Words24;

    use_mnemonic
        .then(|| generate_and_print_mnemonic_code(MNEMONIC_TYPE))
        .transpose()
}

fn get_secure_user_input<S>(request: S) -> std::io::Result<SecStr>
where
    S: std::fmt::Display,
{
    print!("{} ", request);
    std::io::stdout().flush()?;

    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    Ok(SecStr::from(response))
}

fn read_mnemonic_code() -> Result<Mnemonic, GenRestoreKeyError> {
    let phrase = get_secure_user_input("Input mnemonic code: ")
        .map_err(|_| GenRestoreKeyError::MnemonicInputError)?;

    Mnemonic::from_phrase(
        unsafe { std::str::from_utf8_unchecked(phrase.unsecure()) },
        Language::English,
    )
    .map_err(|_| GenRestoreKeyError::MnemonicInputError)
}

pub fn read_and_confirm_passphrase_tty(
    prompt: &str,
) -> Result<String, Box<dyn error::Error>> {
    let passphrase = rpassword::read_password_from_tty(Some(prompt))?;
    if !passphrase.is_empty() {
        let confirmed = rpassword::read_password_from_tty(Some(
            "Enter same passphrase again: ",
        ))?;
        if confirmed != passphrase {
            return Err("Passphrases did not match".into());
        }
    }
    Ok(passphrase)
}

pub fn read_and_confirm_mnemonic_passphrase() -> String {
    match read_and_confirm_passphrase_tty(
        "Enter BIP39 passphrase (empty for none): ",
    ) {
        Ok(mnemonic_passphrase) => mnemonic_passphrase,
        Err(e) => {
            eprint!("{}", e);
            cli::safe_exit(1);
        }
    }
}

/// Read the password for encryption from the file/env/stdin with confirmation.
pub fn read_and_confirm_encryption_password(
    unsafe_dont_encrypt: bool,
) -> Option<String> {
    let password = if unsafe_dont_encrypt {
        println!("Warning: The keypair will NOT be encrypted.");
        None
    } else {
        Some(read_encryption_password("Enter your encryption password: "))
    };
    // Bis repetita for confirmation.
    let to_confirm = if unsafe_dont_encrypt {
        None
    } else {
        Some(read_encryption_password(
            "To confirm, please enter the same encryption password once more: ",
        ))
    };
    if to_confirm != password {
        eprintln!("Your two inputs do not match!");
        cli::safe_exit(1)
    }
    password
}

/// Read the password for encryption/decryption from the file/env/stdin. Exits
/// if all options are empty/invalid.
pub fn read_encryption_password(prompt_msg: &str) -> String {
    let pwd = match env::var("NAMADA_WALLET_PASSWORD_FILE") {
        Ok(path) => fs::read_to_string(path)
            .expect("Something went wrong reading the file"),
        Err(_) => match env::var("NAMADA_WALLET_PASSWORD") {
            Ok(password) => password,
            Err(_) => rpassword::read_password_from_tty(Some(prompt_msg))
                .unwrap_or_default(),
        },
    };
    if pwd.is_empty() {
        eprintln!("Password cannot be empty");
        cli::safe_exit(1)
    }
    pwd
}

#[cfg(test)]
mod tests {
    use bip39::MnemonicType;

    use crate::wallet::generate_and_print_mnemonic_code;

    #[test]
    fn test_generate_mnemonic() {
        const MNEMONIC_TYPE: MnemonicType = MnemonicType::Words12;
        let mnemonic1 =
            generate_and_print_mnemonic_code(MNEMONIC_TYPE).unwrap();
        let mnemonic2 =
            generate_and_print_mnemonic_code(MNEMONIC_TYPE).unwrap();
        assert_ne!(mnemonic1.into_phrase(), mnemonic2.into_phrase());
    }
}
