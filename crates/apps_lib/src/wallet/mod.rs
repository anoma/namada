pub mod defaults;
pub mod pre_genesis;
mod store;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::{env, fs};

use namada_sdk::bip39::{Language, Mnemonic};
use namada_sdk::key::*;
pub use namada_sdk::wallet::alias::Alias;
use namada_sdk::wallet::fs::FsWalletStorage;
use namada_sdk::wallet::store::Store;
use namada_sdk::wallet::{
    ConfirmationResponse, FindKeyError, Wallet, WalletIo,
};
pub use namada_sdk::wallet::{ValidatorData, ValidatorKeys};
use rand_core::OsRng;
pub use store::wallet_file;
use zeroize::Zeroizing;

use crate::cli;
#[derive(Debug, Clone)]
pub struct CliWalletUtils {
    store_dir: PathBuf,
}

impl CliWalletUtils {
    /// Initialize a wallet at the given directory
    pub fn new(store_dir: PathBuf) -> Wallet<Self> {
        Wallet::new(Self { store_dir }, Store::default())
    }
}

impl FsWalletStorage for CliWalletUtils {
    fn store_dir(&self) -> &PathBuf {
        &self.store_dir
    }
}

impl WalletIo for CliWalletUtils {
    type Rng = OsRng;

    fn read_password(confirm: bool) -> Zeroizing<String> {
        let pwd = match env::var("NAMADA_WALLET_PASSWORD_FILE") {
            Ok(path) => Zeroizing::new(
                fs::read_to_string(path)
                    .expect("Something went wrong reading the file"),
            ),
            Err(_) => match env::var("NAMADA_WALLET_PASSWORD") {
                Ok(password) => Zeroizing::new(password),
                Err(_) if confirm => {
                    let prompt = "Enter your encryption password: ";
                    read_and_confirm_passphrase_tty(prompt).unwrap_or_else(
                        |e| {
                            eprintln!("{e}");
                            eprintln!(
                                "Action cancelled, no changes persisted."
                            );
                            cli::safe_exit(1)
                        },
                    )
                }
                Err(_) => {
                    let prompt = "Enter your decryption password: ";
                    rpassword::read_password_from_tty(Some(prompt))
                        .map(Zeroizing::new)
                        .expect("Failed reading password from tty.")
                }
            },
        };
        if confirm && pwd.as_str().is_empty() {
            eprintln!("Password cannot be empty");
            eprintln!("Action cancelled, no changes persisted.");
            cli::safe_exit(1)
        }
        pwd
    }

    fn read_alias(prompt_msg: &str) -> String {
        print!("Choose an alias for {}: ", prompt_msg);
        io::stdout().flush().unwrap();
        let mut alias = String::new();
        io::stdin().read_line(&mut alias).unwrap();
        alias.trim().to_owned()
    }

    fn read_mnemonic_code() -> Option<Mnemonic> {
        let phrase = get_secure_user_input("Input mnemonic code: ")
            .unwrap_or_else(|e| {
                eprintln!("{}", e);
                eprintln!("Action cancelled, no changes persisted.");
                cli::safe_exit(1)
            });
        Mnemonic::from_phrase(phrase.as_ref(), Language::English).ok()
    }

    fn read_mnemonic_passphrase(confirm: bool) -> Zeroizing<String> {
        let prompt = "Enter BIP39 passphrase (empty for none): ";
        let result = if confirm {
            read_and_confirm_passphrase_tty(prompt)
        } else {
            rpassword::read_password_from_tty(Some(prompt)).map(Zeroizing::new)
        };
        result.unwrap_or_else(|e| {
            eprintln!("{}", e);
            cli::safe_exit(1);
        })
    }

    // The given alias has been selected but conflicts with another alias in
    // the store. Offer the user to either replace existing mapping, alter the
    // chosen alias to a name of their choosing, or cancel the aliasing.
    fn show_overwrite_confirmation(
        alias: &Alias,
        alias_for: &str,
    ) -> ConfirmationResponse {
        print!(
            "You're trying to create an alias \"{}\" that already exists for \
             {} in your store.\nWould you like to replace it? \
             s(k)ip/re(p)lace/re(s)elect: ",
            alias, alias_for
        );
        io::stdout().flush().unwrap();

        let mut buffer = String::new();
        // Get the user to select between 3 choices
        match io::stdin().read_line(&mut buffer) {
            Ok(size) if size > 0 => {
                // Isolate the single character representing the choice
                let byte = buffer.chars().next().unwrap();
                buffer.clear();
                match byte {
                    'p' | 'P' => return ConfirmationResponse::Replace,
                    's' | 'S' => {
                        // In the case of reselection, elicit new alias
                        print!("Please enter a different alias: ");
                        io::stdout().flush().unwrap();
                        if io::stdin().read_line(&mut buffer).is_ok() {
                            return ConfirmationResponse::Reselect(
                                buffer.trim().into(),
                            );
                        }
                    }
                    'k' | 'K' => return ConfirmationResponse::Skip,
                    // Input is senseless fall through to repeat prompt
                    _ => {}
                };
            }
            _ => {}
        }
        // Input is senseless fall through to repeat prompt
        println!("Invalid option, try again.");
        Self::show_overwrite_confirmation(alias, alias_for)
    }
}

fn get_secure_user_input<S>(request: S) -> std::io::Result<Zeroizing<String>>
where
    S: std::fmt::Display,
{
    print!("{} ", request);
    std::io::stdout().flush()?;

    let mut response = Zeroizing::default();
    std::io::stdin().read_line(&mut response)?;
    Ok(response)
}

pub fn read_and_confirm_passphrase_tty(
    prompt: &str,
) -> Result<Zeroizing<String>, std::io::Error> {
    let passphrase =
        rpassword::read_password_from_tty(Some(prompt)).map(Zeroizing::new)?;
    if !passphrase.is_empty() {
        let confirmed = rpassword::read_password_from_tty(Some(
            "Enter same passphrase again: ",
        ))
        .map(Zeroizing::new)?;
        if confirmed != passphrase {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Passphrases did not match",
            ));
        }
    }
    Ok(passphrase)
}

/// Generate keypair
/// for signing protocol txs and for the DKG (which will also be stored)
/// A protocol keypair may be optionally provided, indicating that
/// we should reuse a keypair already in the wallet
pub fn gen_validator_keys<U: WalletIo>(
    wallet: &mut Wallet<U>,
    eth_bridge_pk: Option<common::PublicKey>,
    protocol_pk: Option<common::PublicKey>,
    protocol_key_scheme: SchemeType,
) -> Result<ValidatorKeys, FindKeyError> {
    let protocol_keypair = find_secret_key(wallet, protocol_pk, |data| {
        data.keys.protocol_keypair.clone()
    })?;
    let eth_bridge_keypair = find_secret_key(wallet, eth_bridge_pk, |data| {
        data.keys.eth_bridge_keypair.clone()
    })?;
    Ok(store::gen_validator_keys(
        eth_bridge_keypair,
        protocol_keypair,
        protocol_key_scheme,
    ))
}

/// Find a corresponding [`common::SecretKey`] in [`Wallet`], for some
/// [`common::PublicKey`].
///
/// If a key was provided in `maybe_pk`, and it's found in [`Wallet`], we use
/// `extract_key` to retrieve it from [`ValidatorData`].
fn find_secret_key<F, U>(
    wallet: &mut Wallet<U>,
    maybe_pk: Option<common::PublicKey>,
    extract_key: F,
) -> Result<Option<common::SecretKey>, FindKeyError>
where
    F: Fn(&ValidatorData) -> common::SecretKey,
    U: WalletIo,
{
    maybe_pk
        .map(|pk| {
            let pkh = PublicKeyHash::from(&pk);
            wallet
                // TODO(namada#3251): optionally encrypt validator keys
                .find_key_by_pkh(&pkh, None)
                .ok()
                .or_else(|| wallet.get_validator_data().map(extract_key))
                .ok_or_else(|| FindKeyError::KeyNotFound(pkh.to_string()))
        })
        .transpose()
}

/// Save the wallet store to a file.
pub fn save(wallet: &Wallet<CliWalletUtils>) -> std::io::Result<()> {
    wallet
        .save()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
}

/// Load a wallet from the store file.
pub fn load(store_dir: &Path) -> Option<Wallet<CliWalletUtils>> {
    let mut wallet = CliWalletUtils::new(store_dir.to_path_buf());
    if wallet.load().is_err() {
        return None;
    }
    Some(wallet)
}

/// Load a wallet from the store file or create a new wallet without any
/// keys or addresses.
pub fn load_or_new(store_dir: &Path) -> Wallet<CliWalletUtils> {
    let store = self::store::load_or_new(store_dir).unwrap_or_else(|err| {
        eprintln!("Unable to load the wallet: {}", err);
        cli::safe_exit(1)
    });
    let mut wallet = CliWalletUtils::new(store_dir.to_path_buf());
    *wallet.store_mut() = store;
    wallet
}

/// Check if a wallet exists in the given store dir.
pub fn exists(store_dir: &Path) -> bool {
    let file = wallet_file(store_dir);
    file.exists()
}

/// Read the password for encryption from the file/env/stdin, with
/// confirmation if read from stdin.
pub fn read_and_confirm_encryption_password(
    unsafe_dont_encrypt: bool,
) -> Option<Zeroizing<String>> {
    if unsafe_dont_encrypt {
        println!("Warning: The keypair will NOT be encrypted.");
        None
    } else {
        Some(CliWalletUtils::read_password(true))
    }
}

#[cfg(test)]
mod tests {
    use namada_sdk::bip39::MnemonicType;
    use namada_sdk::wallet::WalletIo;

    use super::CliWalletUtils;

    #[test]
    fn test_generate_mnemonic() {
        const MNEMONIC_TYPE: MnemonicType = MnemonicType::Words12;

        let mut rng = rand_core::OsRng;
        let mnemonic1 =
            CliWalletUtils::generate_mnemonic_code(MNEMONIC_TYPE, &mut rng);
        let mnemonic2 =
            CliWalletUtils::generate_mnemonic_code(MNEMONIC_TYPE, &mut rng);
        assert_ne!(mnemonic1.into_phrase(), mnemonic2.into_phrase());
    }
}
