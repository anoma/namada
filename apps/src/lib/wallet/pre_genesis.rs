use std::fs;
use std::path::{Path, PathBuf};

use ark_serialize::{Read, Write};
use file_lock::{FileLock, FileOptions};
use namada::types::key::{common, SchemeType};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use namada::ledger::wallet::pre_genesis::ValidatorWallet;
use namada::ledger::wallet::pre_genesis::ReadError;
use namada::ledger::wallet::pre_genesis::ValidatorStore;
use namada::ledger::wallet::gen_key_to_store;
use namada::ledger::wallet::WalletUtils;
use crate::wallet::store::gen_validator_keys;
use crate::wallet::CliWalletUtils;

use crate::wallet;
use crate::wallet::{store, StoredKeypair};

/// Validator pre-genesis wallet file name
const VALIDATOR_FILE_NAME: &str = "wallet.toml";

/// Get the path to the validator pre-genesis wallet store.
pub fn validator_file_name(store_dir: impl AsRef<Path>) -> PathBuf {
    store_dir.as_ref().join(VALIDATOR_FILE_NAME)
}

/// Generate a new [`ValidatorWallet`] with required pre-genesis keys and
/// store it as TOML at the given path.
pub fn gen_and_store(
    scheme: SchemeType,
    unsafe_dont_encrypt: bool,
    store_dir: &Path,
) -> std::io::Result<ValidatorWallet> {
    let validator = gen(scheme, unsafe_dont_encrypt);
    let data = validator.store.encode();
    let wallet_path = validator_file_name(store_dir);
    // Make sure the dir exists
    let wallet_dir = wallet_path.parent().unwrap();
    fs::create_dir_all(wallet_dir)?;
    // Write the file
    let options =
        FileOptions::new().create(true).write(true).truncate(true);
    let mut filelock =
        FileLock::lock(wallet_path.to_str().unwrap(), true, options)?;
    filelock.file.write_all(&data)?;
    Ok(validator)
}

/// Try to load and decrypt keys, if encrypted, in a [`ValidatorWallet`]
/// from a TOML file.
pub fn load(store_dir: &Path) -> Result<ValidatorWallet, ReadError> {
    let wallet_file = validator_file_name(store_dir);
    match FileLock::lock(
        wallet_file.to_str().unwrap(),
        true,
        FileOptions::new().read(true).write(false),
    ) {
        Ok(mut filelock) => {
            let mut store = Vec::<u8>::new();
            filelock.file.read_to_end(&mut store).map_err(|err| {
                ReadError::ReadWallet(
                    store_dir.to_str().unwrap().into(),
                    err.to_string(),
                )
            })?;
            let store =
                ValidatorStore::decode(store).map_err(ReadError::Decode)?;

            let password = if store.account_key.is_encrypted()
                || store.consensus_key.is_encrypted()
                || store.account_key.is_encrypted()
            {
                Some(CliWalletUtils::read_password("Enter decryption password: "))
            } else {
                None
            };

            let account_key =
                store.account_key.get::<CliWalletUtils>(true, password.clone())?;
            let consensus_key =
                store.consensus_key.get::<CliWalletUtils>(true, password.clone())?;
            let tendermint_node_key =
                store.tendermint_node_key.get::<CliWalletUtils>(true, password)?;

            Ok(ValidatorWallet {
                store,
                account_key,
                consensus_key,
                tendermint_node_key,
            })
        }
        Err(err) => Err(ReadError::ReadWallet(
            wallet_file.to_string_lossy().into_owned(),
            err.to_string(),
        )),
    }
}

/// Generate a new [`ValidatorWallet`] with required pre-genesis keys. Will
/// prompt for password when `!unsafe_dont_encrypt`.
fn gen(scheme: SchemeType, unsafe_dont_encrypt: bool) -> ValidatorWallet {
    let password = CliWalletUtils::read_and_confirm_pwd(unsafe_dont_encrypt);
    let (account_key, account_sk) = gen_key_to_store(scheme, &password);
    let (consensus_key, consensus_sk) = gen_key_to_store(
        // Note that TM only allows ed25519 for consensus key
        SchemeType::Ed25519,
        &password,
    );
    let (tendermint_node_key, tendermint_node_sk) = gen_key_to_store(
        // Note that TM only allows ed25519 for node IDs
        SchemeType::Ed25519,
        &password,
    );
    let validator_keys = gen_validator_keys(None, scheme);
    let store = ValidatorStore {
        account_key,
        consensus_key,
        tendermint_node_key,
        validator_keys,
    };
    ValidatorWallet {
        store,
        account_key: account_sk,
        consensus_key: consensus_sk,
        tendermint_node_key: tendermint_node_sk,
    }
}
