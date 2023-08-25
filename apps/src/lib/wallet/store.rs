use std::fs;
use std::io::prelude::*;
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(not(feature = "dev"))]
use std::str::FromStr;

use ark_std::rand::prelude::*;
use ark_std::rand::SeedableRng;
use fd_lock::RwLock;
#[cfg(not(feature = "dev"))]
use namada::ledger::wallet::store::AddressVpType;
#[cfg(feature = "dev")]
use namada::ledger::wallet::StoredKeypair;
use namada::ledger::wallet::{gen_sk_rng, Store, ValidatorKeys};
#[cfg(not(feature = "dev"))]
use namada::types::address::Address;
use namada::types::key::*;
use namada::types::transaction::EllipticCurve;
use thiserror::Error;

use crate::config::genesis::genesis_config::GenesisConfig;
use crate::wallet::CliWalletUtils;

#[derive(Error, Debug)]
pub enum LoadStoreError {
    #[error("Failed decoding the wallet store: {0}")]
    Decode(toml::de::Error),
    #[error("Failed to read the wallet store from {0}: {1}")]
    ReadWallet(String, String),
    #[error("Failed to write the wallet store: {0}")]
    StoreNewWallet(String),
}

/// Wallet file name
const FILE_NAME: &str = "wallet.toml";

/// Get the path to the wallet store.
pub fn wallet_file(store_dir: impl AsRef<Path>) -> PathBuf {
    store_dir.as_ref().join(FILE_NAME)
}

/// Save the wallet store to a file.
pub fn save(store: &Store, store_dir: &Path) -> std::io::Result<()> {
    let data = store.encode();
    let wallet_path = wallet_file(store_dir);
    // Make sure the dir exists
    let wallet_dir = wallet_path.parent().unwrap();
    fs::create_dir_all(wallet_dir)?;
    // Write the file
    let mut options = fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    let mut lock = RwLock::new(options.open(wallet_path)?);
    let mut guard = lock.write()?;
    guard.write_all(&data)
}

/// Load the store file or create a new one without any keys or addresses.
pub fn load_or_new(store_dir: &Path) -> Result<Store, LoadStoreError> {
    load(store_dir).or_else(|_| {
        let store = Store::default();
        dbg!("new wallet", &store);
        save(&store, store_dir)
            .map_err(|err| LoadStoreError::StoreNewWallet(err.to_string()))?;
        Ok(store)
    })
}

/// Load the store file or create a new one with the default addresses from
/// the genesis file, if not found.
pub fn load_or_new_from_genesis(
    store_dir: &Path,
    genesis_cfg: GenesisConfig,
) -> Result<Store, LoadStoreError> {
    load(store_dir).or_else(|_| {
        let mut store = Store::default();
        add_genesis_addresses(&mut store, genesis_cfg);
        save(&store, store_dir)
            .map_err(|err| LoadStoreError::StoreNewWallet(err.to_string()))?;
        Ok(store)
    })
}

/// Attempt to load the store file.
pub fn load(store_dir: &Path) -> Result<Store, LoadStoreError> {
    let wallet_file = wallet_file(store_dir);
    let mut options = fs::OpenOptions::new();
    options.read(true).write(false);
    let lock = RwLock::new(options.open(&wallet_file).map_err(|err| {
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
            store_dir.to_str().unwrap().parse().unwrap(),
            err.to_string(),
        )
    })?;
    dbg!(store_dir);
    dbg!(Store::decode(store).map_err(LoadStoreError::Decode))
}

/// Add addresses from a genesis configuration.
pub fn add_genesis_addresses(store: &mut Store, genesis: GenesisConfig) {
    for (alias, addr) in
        super::defaults::addresses_from_genesis(genesis.clone())
    {
        store.insert_address::<CliWalletUtils>(alias, addr, true);
    }
    for (alias, token) in &genesis.token {
        if let Some(address) = token.address.as_ref() {
            match Address::from_str(address) {
                Ok(address) => {
                    store.add_vp_type_to_address(AddressVpType::Token, address)
                }
                Err(_) => {
                    tracing::error!(
                        "Weird address for token {alias}: {address}"
                    )
                }
            }
        }
    }
}

/// Generate keypair for signing protocol txs and for the DKG
/// A protocol keypair may be optionally provided
///
/// Note that this removes the validator data.
pub fn gen_validator_keys(
    eth_bridge_keypair: Option<common::SecretKey>,
    protocol_keypair: Option<common::SecretKey>,
    protocol_keypair_scheme: SchemeType,
) -> ValidatorKeys {
    let eth_bridge_keypair = eth_bridge_keypair
        .map(|k| {
            if !matches!(&k, common::SecretKey::Secp256k1(_)) {
                panic!("Ethereum bridge keys can only be of kind Secp256k1");
            }
            k
        })
        .unwrap_or_else(|| gen_sk_rng(SchemeType::Secp256k1));
    let protocol_keypair =
        protocol_keypair.unwrap_or_else(|| gen_sk_rng(protocol_keypair_scheme));
    let dkg_keypair = ferveo_common::Keypair::<EllipticCurve>::new(
        &mut StdRng::from_entropy(),
    );
    ValidatorKeys {
        protocol_keypair,
        eth_bridge_keypair,
        dkg_keypair: Some(dkg_keypair.into()),
    }
}

#[cfg(test)]
mod test_wallet {
    use namada::types::address::Address;

    use super::*;

    #[test]
    fn test_toml_roundtrip_ed25519() {
        let mut store = Store::default();
        let validator_keys =
            gen_validator_keys(None, None, SchemeType::Ed25519);
        store.add_validator_data(
            Address::decode("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5").unwrap(),
            validator_keys
        );
        let data = store.encode();
        let _ = Store::decode(data).expect("Test failed");
    }

    #[test]
    fn test_toml_roundtrip_secp256k1() {
        let mut store = Store::default();
        let validator_keys =
            gen_validator_keys(None, None, SchemeType::Secp256k1);
        store.add_validator_data(
            Address::decode("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5").unwrap(),
            validator_keys
        );
        let data = store.encode();
        let _ = Store::decode(data).expect("Test failed");
    }
}
